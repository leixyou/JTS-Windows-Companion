using System.Net.Http;
using System.Net.WebSockets;
using JTS.WindowsCompanion.Relay;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.Control;

/// <summary>Outbound control-only service lifecycle. No listener, enrollment, credentials, SCM install or RDP dependency.</summary>
public sealed partial class CompanionRelayControlService : IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly IControlRelayConnector _connector;
    private readonly IControlRelayPairings _pairings;
    private readonly CompanionControlHost _host;
    private readonly TimeProvider _clock;
    private readonly RelayControlTiming _timing;
    private readonly CancellationTokenSource _stop = new();
    private readonly Dictionary<Guid, ActiveConnection> _active = [];
    private readonly Dictionary<Guid, DateTimeOffset> _attempted = [];
    private readonly HashSet<string> _revoked = new(StringComparer.Ordinal);
    private RelayControlServiceStatus _status = new(RelayControlServiceState.NotStarted, null);
    private Task? _run;
    private bool _disposed, _drained;
    private string? _lastSessionError;
    private bool _waitForRelayAdmission;
    public RelayControlServiceStatus Status => Volatile.Read(ref _status);
    public string? LastSessionError => Volatile.Read(ref _lastSessionError);

    /// <remarks>Caller owns relay/identity/store and must keep them alive until this service has drained.</remarks>
    public CompanionRelayControlService(RelayControlClient relay, DurableJobStore store,
        IControlGrantProvider grants, IControlRelayPairings pairings, IJobExecutor executor, TimeProvider? clock = null,
        IReadOnlyDictionary<RelayLane, ICompanionRelayLaneHandler>? lanes = null, bool waitForRelayAdmission = false)
        : this(new ControlRelayConnector(relay ?? throw new ArgumentNullException(nameof(relay)), lanes),
            store, grants, pairings, executor, clock ?? TimeProvider.System, RelayControlTiming.Default)
        { _waitForRelayAdmission = waitForRelayAdmission; }

    internal CompanionRelayControlService(IControlRelayConnector connector, DurableJobStore store,
        IControlGrantProvider grants, IControlRelayPairings pairings, IJobExecutor executor, TimeProvider clock, RelayControlTiming timing,
        bool waitForRelayAdmission = false)
    {
        ArgumentNullException.ThrowIfNull(pairings); ArgumentNullException.ThrowIfNull(grants);
        if (pairings.LocalDeviceId != connector.DeviceId) throw new ControlProtocolException("CONTROL_PAIRING_LOCAL_IDENTITY_MISMATCH");
        _connector = connector; _pairings = pairings; _clock = clock; _timing = timing;
        _waitForRelayAdmission = waitForRelayAdmission;
        _host = new(store, new PairingBoundControlGrants(grants, pairings, clock), executor, clock);
    }

    public Task RunAsync(CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_run is not null) throw new ControlProtocolException("CONTROL_RELAY_ALREADY_STARTED");
            // Yield before taking any callbacks so construction/start do not block the caller.
            _run = Task.Run(() => RunCoreAsync(cancellationToken), CancellationToken.None);
            return _run;
        }
    }

    public async ValueTask RevokePairingAsync(string owner, Guid pairingId, CancellationToken token = default)
    {
        ControlPolicyCodec.Identity(owner, pairingId);
        await _pairingLifecycle.WaitAsync(token).ConfigureAwait(false);
        try
        {
            try { await _pairings.RevokeAsync(owner, pairingId, token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
            catch
            {
                SetStatus(RelayControlServiceState.Faulted, "CONTROL_PAIRING_REVOCATION_NOT_DURABLE");
                _stop.Cancel(); throw new ControlProtocolException("CONTROL_PAIRING_REVOCATION_NOT_DURABLE");
            }
            // Cancellation after a durable commit must not skip live cancellation.
            StopPeer(owner);
        }
        finally { _pairingLifecycle.Release(); }
    }

    public ValueTask RevokeGrantDurablyAsync(string owner, Guid grantId, CancellationToken token = default)
        => _host.RevokeGrantDurablyAsync(owner, grantId, token);

    private async Task RunCoreAsync(CancellationToken caller)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(caller, _stop.Token);
        SetStatus(RelayControlServiceState.Connecting);
        Task? loop = null;
        try
        {
            loop = PollLoopAsync(linked.Token);
            var first = await Task.WhenAny(loop, _host.Completion).ConfigureAwait(false);
            if (first == _host.Completion)
            {
                await _host.Completion.ConfigureAwait(false);
                if (!linked.IsCancellationRequested) throw new ControlProtocolException("CONTROL_HOST_STOPPED");
            }
            else await loop.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested) { }
        catch
        {
            SetStatus(RelayControlServiceState.Faulted, "CONTROL_RELAY_STOPPED_UNEXPECTEDLY");
            throw new ControlProtocolException("CONTROL_RELAY_STOPPED_UNEXPECTEDLY");
        }
        finally
        {
            linked.Cancel();
            if (loop is not null) try { await loop.ConfigureAwait(false); } catch { /* Observed above; cleanup must still run. */ }
            await DrainAsync().ConfigureAwait(false);
            if (Status.State != RelayControlServiceState.Faulted) SetStatus(RelayControlServiceState.Stopped);
        }
    }

    private async Task PollLoopAsync(CancellationToken token)
    {
        var nextPresence = DateTimeOffset.MinValue;
        var failures = 0;
        while (true)
        {
            token.ThrowIfCancellationRequested();
            await ReconcilePairingsAsync(token).ConfigureAwait(false);
            try
            {
                if (_clock.GetUtcNow() >= nextPresence)
                {
                    await _connector.TouchPresenceAsync(token).ConfigureAwait(false);
                    _waitForRelayAdmission = false; // Admission loss after the first successful presence remains fatal.
                    nextPresence = _clock.GetUtcNow() + _timing.Presence;
                }
                var offers = await _connector.PollAsync(token).ConfigureAwait(false);
                if (offers.Count > 32) throw new ControlProtocolException("CONTROL_RELAY_OFFER_LIMIT");
                foreach (var offer in offers) await AcceptOfferAsync(offer, token).ConfigureAwait(false);
                failures = 0; SetStatus(RelayControlServiceState.Online);
                await Task.Delay(_timing.Poll, _clock, token).ConfigureAwait(false);
            }
            catch (Exception error) when (!token.IsCancellationRequested && (IsTransient(error)
                || (_waitForRelayAdmission && error is RelayProtocolException { Code: "RELAY_HTTP_401" or "RELAY_HTTP_403" })))
            {
                failures = Math.Min(failures + 1, 16); nextPresence = DateTimeOffset.MinValue;
                SetStatus(RelayControlServiceState.BackingOff, _waitForRelayAdmission && error is RelayProtocolException { Code: "RELAY_HTTP_401" or "RELAY_HTTP_403" }
                    ? "CONTROL_RELAY_ADMISSION_REQUIRED" : "CONTROL_RELAY_NETWORK_UNAVAILABLE");
                var delay = Math.Min(_timing.MaximumBackoff.TotalMilliseconds,
                    _timing.InitialBackoff.TotalMilliseconds * Math.Pow(2, failures - 1));
                // Jitter only within the bound; no synchronized fleet retry storm.
                await Task.Delay(TimeSpan.FromMilliseconds(delay * (0.8 + Random.Shared.NextDouble() * 0.2)), _clock, token).ConfigureAwait(false);
            }
        }
    }

    private static bool IsTransient(Exception error) => error switch
    {
        RelayProtocolException e => e.Code is "RELAY_HTTP_408" or "RELAY_HTTP_429" or "RELAY_HTTP_500" or "RELAY_HTTP_502" or "RELAY_HTTP_503" or "RELAY_HTTP_504",
        HttpRequestException e => e.HttpRequestError is HttpRequestError.NameResolutionError or HttpRequestError.ConnectionError or HttpRequestError.ResponseEnded,
        WebSocketException => true,
        OperationCanceledException => true, // Per-request deadline; the outer stop token is checked by the filter.
        _ => false,
    };

    private void SetStatus(RelayControlServiceState state, string? code = null) => Volatile.Write(ref _status, new(state, code));

    private async Task DrainAsync()
    {
        Task[] sessions;
        lock (_gate) sessions = _active.Values.Select(c => c.Finished.Task).ToArray();
        // Stop the host immediately too, even when a connector fails to acknowledge cancellation.
        var hostStop = _host.DisposeAsync().AsTask();
        try
        {
            await Task.WhenAll(Task.WhenAll(sessions).WaitAsync(TimeSpan.FromSeconds(5)), hostStop).ConfigureAwait(false);
            _drained = true;
        }
        catch
        {
            SetStatus(RelayControlServiceState.Faulted, "CONTROL_RELAY_DRAIN_NOT_CONFIRMED");
            throw new ControlProtocolException("CONTROL_RELAY_DRAIN_NOT_CONFIRMED");
        }
    }

    public async ValueTask DisposeAsync()
    {
        Task? run;
        lock (_gate) { _disposed = true; run = _run; }
        _stop.Cancel();
        if (run is null) { await _host.DisposeAsync().ConfigureAwait(false); _drained = true; SetStatus(RelayControlServiceState.Stopped); }
        else
        {
            try { await run.ConfigureAwait(false); }
            catch when (_drained) { /* The RunAsync caller and Status retain the fault; actual cleanup succeeded. */ }
            catch { await DrainAsync().ConfigureAwait(false); } // Explicit later disposal may finish a previously unconfirmed drain.
        }
    }
}
