using JTS.WindowsCompanion.Relay;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.Control;

/// <summary>Composes authenticated control sessions and one durable scheduler, independently of any desktop.</summary>
public sealed partial class CompanionControlHost : IAsyncDisposable, IJobGrantAuthority
{
    private readonly object _gate = new();
    private readonly IControlGrantProvider _grants;
    private readonly TimeProvider _clock;
    private readonly DurableJobRuntime _runtime;
    private readonly ControlDispatcher _dispatcher;
    private readonly Dictionary<Guid, Connection> _connections = [];
    private readonly HashSet<(string, Guid)> _revoked = [];
    private readonly HashSet<string> _revokedPeers = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource _shutdown = new();
    private readonly SemaphoreSlim _wake = new(0, 1);
    private readonly Task _scheduler;
    private bool _stopping;

    public CompanionControlHost(DurableJobStore store, IControlGrantProvider grants, IJobExecutor executor, TimeProvider? clock = null)
    {
        _grants = grants ?? throw new ArgumentNullException(nameof(grants)); _clock = clock ?? TimeProvider.System;
        _runtime = new DurableJobRuntime(store, this, executor, _clock);
        _dispatcher = new ControlDispatcher(this, store, _runtime);
        _scheduler = Task.Run(ScheduleAsync);
        Wake(); // Reconcile previously queued explicit detached jobs through fresh authorization.
    }

    public Task Completion => _scheduler;

    /// <summary>Local consent UI/service only. Persist first, then stop related tasks/streams; never a remote grant-edit RPC.</summary>
    public async ValueTask RevokeGrantDurablyAsync(string owner, Guid grantId, CancellationToken cancellationToken = default)
    {
        ControlPolicyCodec.Identity(owner, grantId);
        lock (_gate) RequireRunning();
        if (_grants is not IDurableControlGrantProvider durable)
            throw new ControlProtocolException("CONTROL_DURABLE_REVOCATION_UNAVAILABLE");
        try { await durable.RevokeAsync(owner, grantId, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch
        {
            // A storage failure must not leave an apparently revoked running session.
            // Stop this host; the UI must report that revocation was NOT durably confirmed.
            _shutdown.Cancel(); throw new ControlProtocolException("CONTROL_REVOCATION_NOT_DURABLE");
        }
        RevokeGrant(owner, grantId); // Do not observe caller cancellation after a successful durable commit.
    }

    /// <summary>No public plaintext/business-stream entry point: this method itself completes pinned mutual TLS and binding.</summary>
    public Task ServeAsync(Stream carrier, RelayEndpointIdentity identity, RelayPeerTrust peer,
        RelayBinding binding, CancellationToken cancellationToken = default)
        => ServeConnectionAsync(binding,
            token => RelaySecureStream.AuthenticateAsync(carrier, identity, peer, binding, false, token),
            carrier.Dispose, cancellationToken);

    /// <summary>Accepts one outbound relay offer; inner pinned TLS is still mandatory before control dispatch.</summary>
    public Task ServeRelayAsync(RelayControlClient relay, RelayChannelOffer offer, RelayPeerTrust peer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(relay); ArgumentNullException.ThrowIfNull(offer);
        if (offer.Binding.CompanionDeviceId != relay.DeviceId) throw new ControlProtocolException("CONTROL_COMPANION_IDENTITY_REQUIRED");
        return ServeConnectionAsync(offer.Binding, token => relay.OpenSecureChannelAsync(offer, peer, token), null, cancellationToken);
    }

    private async Task ServeConnectionAsync(RelayBinding binding,
        Func<CancellationToken, Task<System.Net.Security.SslStream>> authenticate, Action? closeCarrier, CancellationToken cancellationToken)
    {
        binding.Validate();
        if (binding.Lane != RelayLane.Control) throw new ControlProtocolException("CONTROL_LANE_REQUIRED");
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _shutdown.Token);
        var connection = new Connection(binding.ControllerDeviceId, linked);
        lock (_gate)
        {
            RequireRunning();
            if (PeerBlocked(connection.Owner)) throw new ControlProtocolException("CONTROL_PAIRING_REVOKED");
            if (_connections.Count >= 16 || _connections.Values.Count(c => c.Owner == connection.Owner) >= 4
                || !_connections.TryAdd(binding.SessionId, connection))
                throw new ControlProtocolException("CONTROL_CONNECTION_LIMIT");
        }
        using var closeOnCancel = linked.Token.Register(() => closeCarrier?.Invoke());
        try
        {
            await using var tls = await authenticate(linked.Token).ConfigureAwait(false);
            using var closeTlsOnCancel = linked.Token.Register(tls.Dispose);
            lock (_gate)
            {
                RequireRunning();
                if (PeerBlocked(connection.Owner)) throw new ControlProtocolException("CONTROL_PAIRING_REVOKED");
                _runtime.SetOwnerConnected(connection.Owner, true);
                connection.Authenticated = true;
            }
            await _dispatcher.ServeAsync(tls, connection.Owner, linked.Token).ConfigureAwait(false);
        }
        finally
        {
            try { lock (_gate)
            {
                _connections.Remove(binding.SessionId);
                if (connection.Authenticated && !_connections.Values.Any(c => c.Authenticated && c.Owner == connection.Owner))
                    _runtime.SetOwnerConnected(connection.Owner, false);
            } }
            finally { connection.Finished.TrySetResult(); closeCarrier?.Invoke(); }
        }
    }

    /// <summary>Call only after the local grant provider durably records revocation. This hook cancels online tasks and sessions.</summary>
    public void RevokeGrant(string owner, Guid grantId)
    {
        Connection[] affected;
        lock (_gate)
        {
            RequireRunning();
            if (!_revoked.Contains((owner, grantId)) && _revoked.Count >= 4096)
            { _shutdown.Cancel(); throw new ControlProtocolException("CONTROL_AUTHORIZATION_CAPACITY"); }
            _runtime.RevokeGrant(owner, grantId);
            _revoked.Add((owner, grantId));
            affected = _connections.Values.Where(c => c.Owner == owner).ToArray();
        }
        // An authenticated owner may use several grants per stream; conservatively close its streams.
        foreach (var connection in affected)
            try { connection.Cancel.Cancel(); } catch (ObjectDisposedException) { /* Session already drained. */ }
    }

    /// <summary>Call after durable local pairing revocation. Does not revoke unrelated device capabilities.</summary>
    public void RevokePeer(string owner)
    {
        if (owner is not { Length: 64 } || owner.Any(c => !"0123456789abcdef".Contains(c)))
            throw new ArgumentException("An exact peer identity is required.");
        Connection[] affected;
        lock (_gate)
        {
            RequireRunning();
            if (!_revokedPeers.Contains(owner) && _revokedPeers.Count >= 4096)
            { _shutdown.Cancel(); throw new ControlProtocolException("CONTROL_AUTHORIZATION_CAPACITY"); }
            _revokedPeers.Add(owner); _runtime.RevokeOwner(owner);
            _readmittedPeerGrants.Remove(owner);
            _peerRevocationVersions[owner] = _peerRevocationVersions.GetValueOrDefault(owner) + 1;
            affected = _connections.Values.Where(c => c.Owner == owner).ToArray();
        }
        foreach (var connection in affected)
            try { connection.Cancel.Cancel(); } catch (ObjectDisposedException) { }
    }

    internal async ValueTask<ControlGrant> RequireGrantAsync(string owner, Guid grantId, ControlOperation operation, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var grant = await _grants.FindAsync(owner, grantId, token).AsTask().WaitAsync(token).ConfigureAwait(false);
        lock (_gate)
        {
            RequireRunning();
            if (PeerGrantBlocked(owner, grantId) || _revoked.Contains((owner, grantId)) || grant is null || grant.OwnerDeviceId != owner || grant.GrantId != grantId
                || grant.ExpiresAt <= _clock.GetUtcNow() || !grant.Allows(operation))
                throw new ControlProtocolException("CONTROL_GRANT_REJECTED");
            return grant;
        }
    }

    async ValueTask<bool> IJobGrantAuthority.CanExecuteAsync(JobBinding binding, CancellationToken cancellationToken)
    {
        try
        {
            var grant = await RequireGrantAsync(binding.OwnerDeviceId, binding.GrantId, ControlOperation.Submit, cancellationToken).ConfigureAwait(false);
            return grant.Allows(binding);
        }
        catch (ControlProtocolException e) when (e.Code == "CONTROL_GRANT_REJECTED") { return false; }
    }

    internal void Wake() { try { _wake.Release(); } catch (SemaphoreFullException) { } }
    private async Task ScheduleAsync()
    {
        try
        {
            while (!_shutdown.IsCancellationRequested)
            {
                await _wake.WaitAsync(_shutdown.Token).ConfigureAwait(false);
                while (await _runtime.RunNextAsync(_shutdown.Token).ConfigureAwait(false)) { }
            }
        }
        catch (OperationCanceledException) when (_shutdown.IsCancellationRequested) { }
        catch { _shutdown.Cancel(); throw new ControlProtocolException("CONTROL_SCHEDULER_FAILED"); }
    }

    private void RequireRunning()
    {
        if (_stopping || _shutdown.IsCancellationRequested) throw new ControlProtocolException("CONTROL_HOST_STOPPING");
    }

    public async ValueTask DisposeAsync()
    {
        Task[] sessions;
        lock (_gate) { _stopping = true; sessions = _connections.Values.Select(c => c.Finished.Task).ToArray(); }
        _shutdown.Cancel();
        await Task.WhenAll(sessions).WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        try { await _scheduler.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false); }
        finally { await _runtime.DisposeAsync().ConfigureAwait(false); }
        // The caller closes its store only after all sessions/executors have drained.
    }

    private sealed class Connection(string owner, CancellationTokenSource cancel)
    {
        internal string Owner { get; } = owner;
        internal CancellationTokenSource Cancel { get; } = cancel;
        internal bool Authenticated { get; set; }
        internal TaskCompletionSource Finished { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}
