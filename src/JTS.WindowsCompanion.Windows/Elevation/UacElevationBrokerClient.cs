using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Elevation;
using JTS.WindowsCompanion.Files;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Shell;
using JTS.WindowsCompanion.Windows.Security;

namespace JTS.WindowsCompanion.Windows.Elevation;

public sealed class UacElevationBrokerClient : IElevationBrokerClient
{
    internal const string BrokerFileName = "JTS.WindowsCompanion.UacBroker.exe";
    private static readonly TimeSpan ConnectionTimeout = TimeSpan.FromMinutes(2);
    private readonly string _brokerExecutablePath;
    private readonly ElevationActionBuilder _actions;
    private readonly IElevationConsentPrompt _consent;
    private readonly IReleaseExecutableTrustVerifier _trust;
    private readonly TimeProvider _timeProvider;
    private readonly ConcurrentDictionary<Guid, BrokerLeaseSession> _sessions = new();
    private bool _disposed;

    public UacElevationBrokerClient(string brokerExecutablePath, FileSandbox sandbox)
        : this(
            brokerExecutablePath,
            sandbox,
            new WindowsElevationConsentPrompt(),
            CreateProductionTrustVerifier(),
            TimeProvider.System)
    {
    }

    internal UacElevationBrokerClient(
        string brokerExecutablePath,
        FileSandbox sandbox,
        IElevationConsentPrompt consent,
        IReleaseExecutableTrustVerifier trust,
        TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(brokerExecutablePath);
        _brokerExecutablePath = Path.GetFullPath(brokerExecutablePath);
        _actions = new ElevationActionBuilder(sandbox ?? throw new ArgumentNullException(nameof(sandbox)));
        _consent = consent ?? throw new ArgumentNullException(nameof(consent));
        _trust = trust ?? throw new ArgumentNullException(nameof(trust));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public bool IsConfigured => !_disposed;

    public int ActiveLeaseCount
    {
        get
        {
            StopExpiredSessions();
            var now = _timeProvider.GetUtcNow();
            return _sessions.Count(pair => pair.Value.Lease.ExpiresAt > now);
        }
    }

    public async ValueTask<ElevationLease> RequestAsync(
        PowerShellElevationRequest request,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The UAC broker is available only on Windows.");
        }

        await RemoveExpiredSessionsAsync().ConfigureAwait(false);
        if (!_sessions.IsEmpty)
        {
            throw new CompanionProtocolException(
                "ELEVATION_BUSY",
                "Only one temporary elevation lease can be active for this Windows session.");
        }

        var (action, duration) = _actions.Build(request);
        using var brokerFileLock = _trust.OpenVerifiedFile(_brokerExecutablePath, BrokerFileName);
        if (!await _consent.ConfirmAsync(action, duration, cancellationToken).ConfigureAwait(false))
        {
            throw new CompanionProtocolException("ELEVATION_DECLINED", "The Windows user declined the elevation request.");
        }

        var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var pipeName = $"JTS.Terminal.Elevation.{Guid.NewGuid():N}";
        var cancellationEventName = $"Local\\JTS.Terminal.Elevation.Cancel.{Guid.NewGuid():N}";
        using var cancellationEvent = new EventWaitHandle(
            false,
            EventResetMode.ManualReset,
            cancellationEventName);
        var pipe = new NamedPipeServerStream(
            pipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
            64 * 1024,
            64 * 1024);
        IBrokerProcessLifetime? process = null;
        try
        {
            process = StartBroker(pipeName, nonce, cancellationEventName);
            using var timeout = new CancellationTokenSource(ConnectionTimeout, _timeProvider);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);
            await pipe.WaitForConnectionAsync(linked.Token).ConfigureAwait(false);
            if (NamedPipePeerProcess.GetClientProcessId(pipe) != process.Id)
            {
                throw new UnauthorizedAccessException("The elevation pipe peer is not the launched broker process.");
            }

            var hello = await LocalIpcJsonCodec.ReadAsync<ElevationBrokerMessage>(pipe, linked.Token).ConfigureAwait(false);
            ValidateResponse(hello, ElevationBrokerMessageKind.Hello, nonce, hello.MessageId);
            var messageId = Guid.NewGuid();
            await LocalIpcJsonCodec.WriteAsync(
                pipe,
                Message(messageId, ElevationBrokerMessageKind.OpenLease, nonce, new ElevationBrokerOpenLease(
                    action,
                    checked((int)duration.TotalMilliseconds))),
                linked.Token).ConfigureAwait(false);
            var response = await LocalIpcJsonCodec.ReadAsync<ElevationBrokerMessage>(pipe, linked.Token).ConfigureAwait(false);
            ValidateResponse(response, ElevationBrokerMessageKind.LeaseOpened, nonce, messageId);
            var lease = Deserialize<ElevationLease>(response.Payload);
            var grant = lease.Actions?.SingleOrDefault(candidate => candidate.ActionId == action.ActionId);
            var now = _timeProvider.GetUtcNow();
            if (lease.LeaseId == Guid.Empty
                || lease.ExpiresAt <= now
                || lease.ExpiresAt - now > ElevationLeaseManager.MaximumDuration
                || lease.ExpiresAt - lease.IssuedAt <= TimeSpan.Zero
                || lease.ExpiresAt - lease.IssuedAt > ElevationLeaseManager.MaximumDuration
                || lease.Actions?.Count != 1
                || grant is null
                || !string.Equals(grant.PayloadSha256, action.PayloadSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("The elevation broker returned an invalid lease.");
            }

            var session = new BrokerLeaseSession(
                process,
                pipe,
                nonce,
                lease,
                action,
                new EventWaitHandle(false, EventResetMode.ManualReset, cancellationEventName),
                _timeProvider);
            if (!_sessions.TryAdd(lease.LeaseId, session))
            {
                process = null;
                await session.DisposeAsync().ConfigureAwait(false);
                throw new InvalidOperationException("The elevation broker returned a duplicate lease ID.");
            }

            process = null;
            return lease;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new CompanionProtocolException("UAC_TIMEOUT", "Windows UAC approval timed out.");
        }
        catch (Win32Exception exception) when (exception.NativeErrorCode == 1223)
        {
            throw new CompanionProtocolException("UAC_CANCELLED", "The Windows user cancelled UAC.");
        }
        finally
        {
            if (process is not null)
            {
                try
                {
                    _ = cancellationEvent.Set();
                }
                finally
                {
                    try
                    {
                        pipe.Dispose();
                    }
                    finally
                    {
                        try
                        {
                            await BrokerProcessShutdown.StopAsync(process, _timeProvider).ConfigureAwait(false);
                        }
                        finally
                        {
                            process.Dispose();
                        }
                    }
                }
            }
        }
    }

    public async ValueTask<ShellExecutionResult> ExecuteAsync(
        ShellExecutionRequest request,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (request.ElevationLeaseId is not { } leaseId
            || !_sessions.TryGetValue(leaseId, out var session))
        {
            throw new CompanionProtocolException("ELEVATION_LEASE_REQUIRED", "The elevation lease is missing or expired.");
        }

        if (session.Lease.ExpiresAt <= _timeProvider.GetUtcNow())
        {
            await RemoveSessionAsync(leaseId, session).ConfigureAwait(false);
            throw new CompanionProtocolException("ELEVATION_LEASE_REQUIRED", "The elevation lease is missing or expired.");
        }

        var action = _actions.RebuildForExecution(request, session.Action);
        try
        {
            var response = await session.ExchangeAsync(
                ElevationBrokerMessageKind.Execute,
                new ElevationBrokerExecute(leaseId, action.ActionId, action),
                cancellationToken).ConfigureAwait(false);
            EnsureBrokerSuccess(response, ElevationBrokerMessageKind.ExecutionResult);
            return Deserialize<ShellExecutionResult>(response.Payload);
        }
        catch
        {
            await RemoveSessionAsync(leaseId, session).ConfigureAwait(false);
            throw;
        }
    }

    public async ValueTask<ElevationLease> GetStatusAsync(Guid leaseId, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (!_sessions.TryGetValue(leaseId, out var session))
        {
            throw new CompanionProtocolException("ELEVATION_LEASE_REQUIRED", "The elevation lease is missing or expired.");
        }

        if (session.Lease.ExpiresAt <= _timeProvider.GetUtcNow())
        {
            await RemoveSessionAsync(leaseId, session).ConfigureAwait(false);
            throw new CompanionProtocolException("ELEVATION_LEASE_REQUIRED", "The elevation lease is missing or expired.");
        }

        try
        {
            var response = await session.ExchangeAsync(
                ElevationBrokerMessageKind.Status,
                new ElevationBrokerLeaseId(leaseId),
                cancellationToken).ConfigureAwait(false);
            EnsureBrokerSuccess(response, ElevationBrokerMessageKind.LeaseStatus);
            var lease = Deserialize<ElevationLease>(response.Payload);
            session.Lease = lease;
            return lease;
        }
        catch
        {
            await RemoveSessionAsync(leaseId, session).ConfigureAwait(false);
            throw;
        }
    }

    public async ValueTask ReleaseAsync(Guid leaseId, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (!_sessions.TryRemove(leaseId, out var session))
        {
            return;
        }

        // Revocation cleanup is deliberately non-cancelable once the lease is removed.
        _ = cancellationToken;
        await session.DisposeAsync().ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        var sessions = _sessions.ToArray();
        _sessions.Clear();
        foreach (var pair in sessions)
        {
            await pair.Value.DisposeAsync().ConfigureAwait(false);
        }
    }

    private IBrokerProcessLifetime StartBroker(string pipeName, string nonce, string cancellationEventName)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = _brokerExecutablePath,
            UseShellExecute = true,
            Verb = "runas",
        };
        startInfo.ArgumentList.Add("--pipe");
        startInfo.ArgumentList.Add(pipeName);
        startInfo.ArgumentList.Add("--nonce");
        startInfo.ArgumentList.Add(nonce);
        startInfo.ArgumentList.Add("--cancel-event");
        startInfo.ArgumentList.Add(cancellationEventName);
        return SystemBrokerProcessLifetime.Start(startInfo);
    }

    private static IReleaseExecutableTrustVerifier CreateProductionTrustVerifier()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The UAC broker is available only on Windows.");
        }

        var agentPath = Environment.ProcessPath
            ?? throw new InvalidOperationException("The running agent executable path is unavailable.");
        return ReleaseManifestExecutableTrustVerifier.ForExecutable(agentPath);
    }

    private static ElevationBrokerMessage Message<T>(
        Guid messageId,
        ElevationBrokerMessageKind kind,
        string nonce,
        T payload) => new(
            ElevationBrokerSession.ProtocolVersion,
            messageId,
            kind,
            nonce,
            ControlMessageSerializer.ToElement(payload));

    private static void ValidateResponse(
        ElevationBrokerMessage response,
        ElevationBrokerMessageKind expected,
        string nonce,
        Guid messageId)
    {
        if (response.Version != ElevationBrokerSession.ProtocolVersion
            || response.MessageId != messageId
            || response.Kind != expected
            || !string.Equals(response.Nonce, nonce, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The elevation broker response is invalid.");
        }
    }

    private static void EnsureBrokerSuccess(
        ElevationBrokerMessage response,
        ElevationBrokerMessageKind expected)
    {
        if (response.Kind == ElevationBrokerMessageKind.Error)
        {
            var error = Deserialize<ElevationBrokerError>(response.Payload);
            throw new CompanionProtocolException(error.Code, error.Message);
        }

        if (response.Kind != expected)
        {
            throw new InvalidDataException("The elevation broker returned an unexpected response.");
        }
    }

    private static T Deserialize<T>(JsonElement element) =>
        element.Deserialize<T>(ControlMessageSerializer.Options)
        ?? throw new InvalidDataException("The elevation broker response payload is missing.");

    private void StopExpiredSessions()
    {
        var now = _timeProvider.GetUtcNow();
        foreach (var session in _sessions.Values.Where(candidate => candidate.Lease.ExpiresAt <= now))
        {
            session.BeginStop();
        }
    }

    private async Task RemoveExpiredSessionsAsync()
    {
        var now = _timeProvider.GetUtcNow();
        foreach (var pair in _sessions.Where(candidate => candidate.Value.Lease.ExpiresAt <= now).ToArray())
        {
            await RemoveSessionAsync(pair.Key, pair.Value).ConfigureAwait(false);
        }
    }

    private async Task RemoveSessionAsync(Guid leaseId, BrokerLeaseSession expected)
    {
        if (_sessions.TryGetValue(leaseId, out var current)
            && ReferenceEquals(current, expected)
            && _sessions.TryRemove(leaseId, out var removed))
        {
            await removed.DisposeAsync().ConfigureAwait(false);
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    internal sealed class BrokerLeaseSession : IAsyncDisposable
    {
        private readonly IBrokerProcessLifetime _process;
        private readonly NamedPipeServerStream _pipe;
        private readonly string _nonce;
        private readonly SemaphoreSlim _exchangeLock = new(1, 1);
        private readonly EventWaitHandle _cancellationEvent;
        private readonly TimeProvider _timeProvider;
        private readonly object _stopLock = new();
        private ITimer? _expirationTimer;
        private Task? _shutdownTask;

        public BrokerLeaseSession(
            IBrokerProcessLifetime process,
            NamedPipeServerStream pipe,
            string nonce,
            ElevationLease lease,
            ElevatedPowerShellActionDescriptor action,
            EventWaitHandle cancellationEvent,
            TimeProvider timeProvider)
        {
            _process = process;
            _pipe = pipe;
            _nonce = nonce;
            Lease = lease;
            Action = action;
            _cancellationEvent = cancellationEvent;
            _timeProvider = timeProvider;
            var dueTime = lease.ExpiresAt - _timeProvider.GetUtcNow();
            var expirationTimer = _timeProvider.CreateTimer(
                static state => ((BrokerLeaseSession)state!).BeginStop(),
                this,
                dueTime > TimeSpan.Zero ? dueTime : TimeSpan.Zero,
                Timeout.InfiniteTimeSpan);
            lock (_stopLock)
            {
                if (_shutdownTask is null)
                {
                    _expirationTimer = expirationTimer;
                }
                else
                {
                    expirationTimer.Dispose();
                }
            }
        }

        public ElevationLease Lease { get; set; }

        public ElevatedPowerShellActionDescriptor Action { get; }

        public async ValueTask<ElevationBrokerMessage> ExchangeAsync<T>(
            ElevationBrokerMessageKind kind,
            T payload,
            CancellationToken cancellationToken)
        {
            await _exchangeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (_process.HasExited || !_pipe.IsConnected)
                {
                    throw new CompanionProtocolException("ELEVATION_BROKER_STOPPED", "The UAC broker is no longer running.");
                }

                var messageId = Guid.NewGuid();
                await LocalIpcJsonCodec.WriteAsync(
                    _pipe,
                    Message(messageId, kind, _nonce, payload),
                    cancellationToken).ConfigureAwait(false);
                var response = await LocalIpcJsonCodec.ReadAsync<ElevationBrokerMessage>(_pipe, cancellationToken).ConfigureAwait(false);
                if (response.Version != ElevationBrokerSession.ProtocolVersion
                    || response.MessageId != messageId
                    || !string.Equals(response.Nonce, _nonce, StringComparison.Ordinal))
                {
                    throw new InvalidDataException("The elevation broker response is invalid.");
                }

                return response;
            }
            finally
            {
                _exchangeLock.Release();
            }
        }

        public void BeginStop()
        {
            lock (_stopLock)
            {
                if (_shutdownTask is not null)
                {
                    return;
                }

                _expirationTimer?.Dispose();
                _expirationTimer = null;
                _shutdownTask = StopCoreAsync();
            }
        }

        public async ValueTask DisposeAsync()
        {
            BeginStop();
            Task shutdown;
            lock (_stopLock)
            {
                shutdown = _shutdownTask!;
            }

            await shutdown.ConfigureAwait(false);
        }

        private async Task StopCoreAsync()
        {
            try
            {
                _ = _cancellationEvent.Set();
            }
            finally
            {
                try
                {
                    _pipe.Dispose();
                }
                finally
                {
                    try
                    {
                        await BrokerProcessShutdown.StopAsync(_process, _timeProvider).ConfigureAwait(false);
                    }
                    finally
                    {
                        _process.Dispose();
                        _cancellationEvent.Dispose();
                    }
                }
            }
        }
    }
}
