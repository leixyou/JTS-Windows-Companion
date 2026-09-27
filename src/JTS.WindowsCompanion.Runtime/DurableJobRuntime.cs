using System.Security.Cryptography;

namespace JTS.WindowsCompanion.Runtime;

/// <summary>Explicitly pumped, serial job scheduler. No service, user impersonation or command executor is installed implicitly.</summary>
public sealed class DurableJobRuntime : IAsyncDisposable
{
    private readonly DurableJobStore _store;
    private readonly IJobGrantAuthority _authority;
    private readonly IJobExecutor _executor;
    private readonly TimeProvider _clock;
    private readonly SemaphoreSlim _dispatch = new(1, 1);
    private readonly object _gate = new();
    private readonly HashSet<string> _connected = new(StringComparer.Ordinal);
    private readonly HashSet<(string Owner, Guid Grant)> _revoked = [];
    private readonly HashSet<string> _revokedOwners = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource _shutdown = new();
    private ActiveJob? _active;
    private bool _stopping;
    private bool _authorizationCapacityExceeded;
    private bool _executorStateUnknown;
    private bool _disposed;

    public DurableJobRuntime(DurableJobStore store, IJobGrantAuthority authority, IJobExecutor executor, TimeProvider? clock = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _authority = authority ?? throw new ArgumentNullException(nameof(authority));
        _executor = executor ?? throw new ArgumentNullException(nameof(executor));
        _clock = clock ?? TimeProvider.System;
        _store.AttachRuntime();
    }

    public async Task<JobSnapshot> SubmitAsync(JobSubmission submission, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(submission);
        // Take a private bounded copy before asynchronous authorization to prevent caller buffer mutation.
        if (submission.Payload.Length is 0 || submission.Payload.Length > _store.Limits.MaximumPayloadBytes)
            throw new JobRuntimeException("JOB_PAYLOAD_INVALID");
        var bytes = submission.Payload.ToArray();
        try
        {
            if (JobBinding.Hash(bytes) != submission.Binding.PayloadSha256) throw new JobRuntimeException("JOB_PAYLOAD_INVALID");
            var stable = new JobSubmission(submission.Binding.RequestId, submission.Binding.Kind,
                submission.Binding.OwnerDeviceId, submission.Binding.GrantId, submission.Binding.Deadline,
                bytes, submission.Binding.AllowDisconnected);
            lock (_gate)
            {
                RequireRunning();
                _store.ValidateSubmission(stable.Binding);
                RequireGrant(stable.Binding);
            }
            if (!await _authority.CanExecuteAsync(stable.Binding, cancellationToken).ConfigureAwait(false))
                throw new JobRuntimeException("JOB_GRANT_REJECTED");
            lock (_gate)
            {
                RequireRunning();
                RequireGrant(stable.Binding);
                if (!stable.Binding.AllowDisconnected && !_connected.Contains(stable.Binding.OwnerDeviceId))
                    throw new JobRuntimeException("JOB_OWNER_OFFLINE");
                return _store.Submit(stable);
            }
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public void SetOwnerConnected(string ownerDeviceId, bool connected)
    {
        if (!JobBinding.IsHash(ownerDeviceId)) throw new ArgumentException("A device fingerprint is required.");
        lock (_gate)
        {
            RequireRunning();
            if (connected)
            {
                if (!_connected.Contains(ownerDeviceId) && _connected.Count >= _store.Limits.MaximumConnectedOwners)
                    throw new JobRuntimeException("JOB_PRESENCE_CAPACITY");
                _connected.Add(ownerDeviceId); return;
            }
            _connected.Remove(ownerDeviceId);
            foreach (var job in _store.ActiveFor(ownerDeviceId, grant: null, disconnectedOnly: true))
                CancelCore(job.Binding, "OWNER_DISCONNECTED");
        }
    }

    /// <summary>The host must durably revoke the grant in its authority before calling this immediate cancellation hook.</summary>
    public void RevokeGrant(string ownerDeviceId, Guid grantId)
    {
        if (!JobBinding.IsHash(ownerDeviceId) || grantId == Guid.Empty) throw new ArgumentException("An exact owner and grant are required.");
        lock (_gate)
        {
            RequireRunning();
            if (!_revoked.Contains((ownerDeviceId, grantId)) && _revoked.Count >= _store.Limits.MaximumRememberedRevocations)
            {
                // Never evict a revocation and accidentally admit an in-flight stale authority result.
                // The host must repair its bounded admission state before constructing a new runtime.
                _authorizationCapacityExceeded = true;
                foreach (var job in _store.ActiveFor(owner: null, grant: null, disconnectedOnly: false))
                    CancelCore(job.Binding, "AUTHORIZATION_CACHE_CAPACITY");
                throw new JobRuntimeException("JOB_AUTHORIZATION_CAPACITY");
            }
            _revoked.Add((ownerDeviceId, grantId));
            foreach (var job in _store.ActiveFor(ownerDeviceId, grantId, disconnectedOnly: false))
                CancelCore(job.Binding, "GRANT_REVOKED");
        }
    }

    /// <summary>The host must durably revoke device pairing first. Also stops explicitly detached work.</summary>
    public void RevokeOwner(string ownerDeviceId)
    {
        if (!JobBinding.IsHash(ownerDeviceId)) throw new ArgumentException("An exact owner is required.");
        lock (_gate)
        {
            RequireRunning();
            if (!_revokedOwners.Contains(ownerDeviceId) && _revokedOwners.Count >= _store.Limits.MaximumRememberedRevocations)
            {
                _authorizationCapacityExceeded = true;
                foreach (var job in _store.ActiveFor(null, null, false)) CancelCore(job.Binding, "AUTHORIZATION_CACHE_CAPACITY");
                throw new JobRuntimeException("JOB_AUTHORIZATION_CAPACITY");
            }
            _revokedOwners.Add(ownerDeviceId); _connected.Remove(ownerDeviceId);
            foreach (var job in _store.ActiveFor(ownerDeviceId, null, false)) CancelCore(job.Binding, "PAIRING_REVOKED");
        }
    }

    public JobSnapshot Cancel(Guid requestId, string ownerDeviceId, Guid grantId)
    {
        lock (_gate)
        {
            RequireRunning();
            var snapshot = _store.Get(requestId, ownerDeviceId, grantId);
            CancelCore(snapshot.Binding, "OWNER_CANCELLED");
            return _store.Get(requestId, ownerDeviceId, grantId);
        }
    }

    /// <summary>Processes at most one queued receipt. Repeated calls never replay running/interrupted jobs.</summary>
    public async Task<bool> RunNextAsync(CancellationToken cancellationToken = default)
    {
        using var dispatchCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _shutdown.Token);
        await _dispatch.WaitAsync(dispatchCancellation.Token).ConfigureAwait(false);
        byte[]? payload = null;
        ActiveJob? active = null;
        try
        {
            JobSnapshot? queued;
            lock (_gate) { RequireRunning(); queued = _store.NextQueued(); }
            if (queued is null) return false;
            var binding = queued.Binding;
            var authorized = await _authority.CanExecuteAsync(binding, dispatchCancellation.Token).ConfigureAwait(false);
            lock (_gate)
            {
                RequireRunning();
                if (_store.Get(binding.RequestId, binding.OwnerDeviceId, binding.GrantId).State != DurableJobState.Queued) return true;
                if (binding.Deadline <= _clock.GetUtcNow())
                { _store.Finish(binding.RequestId, DurableJobState.Expired, "DEADLINE_EXPIRED"); return true; }
                if (!authorized || _revokedOwners.Contains(binding.OwnerDeviceId) || _revoked.Contains((binding.OwnerDeviceId, binding.GrantId)))
                { _store.Finish(binding.RequestId, DurableJobState.Cancelled, "GRANT_REVOKED"); return true; }
                if (!binding.AllowDisconnected && !_connected.Contains(binding.OwnerDeviceId))
                { _store.Finish(binding.RequestId, DurableJobState.Cancelled, "OWNER_DISCONNECTED"); return true; }
                if (!_store.Start(binding.RequestId)) return true;
                active = new ActiveJob(binding, dispatchCancellation.Token, binding.Deadline - _clock.GetUtcNow(), _clock);
                _active = active;
            }
            try
            {
                payload = _store.ReadPayload(binding);
                active.Cancellation.Token.ThrowIfCancellationRequested();
                var result = await _executor.ExecuteAsync(binding, payload,
                    new OutputSink(this, active), active.Cancellation.Token).ConfigureAwait(false);
                lock (_gate)
                {
                    if (active.Cancellation.IsCancellationRequested || _clock.GetUtcNow() >= binding.Deadline) CompleteCancellation(active);
                    else _store.Finish(binding.RequestId, result.Success ? DurableJobState.Succeeded : DurableJobState.Failed, result.ResultCode);
                }
            }
            catch (JobExecutionStateUnknownException)
            {
                lock (_gate)
                {
                    _executorStateUnknown = true;
                    try { _store.QuarantineExecution(binding.RequestId, "EXECUTOR_STATE_UNKNOWN"); }
                    finally { _shutdown.Cancel(); }
                }
                // Fault the host scheduler as well as closing admission. An automatic executor restart is unsafe.
                throw new JobRuntimeException("JOB_EXECUTOR_STATE_UNKNOWN");
            }
            catch (OperationCanceledException) when (active.Cancellation.IsCancellationRequested)
            { lock (_gate) CompleteCancellation(active); }
            catch (JobRuntimeException exception)
            {
                lock (_gate)
                {
                    if (active.Cancellation.IsCancellationRequested) CompleteCancellation(active);
                    else _store.Finish(binding.RequestId, DurableJobState.Failed,
                        exception.Code is "JOB_OUTPUT_LIMIT" or "JOB_PAYLOAD_AUTHENTICATION_FAILED" ? exception.Code : "JOB_EXECUTION_FAILED");
                }
            }
            catch (Exception)
            {
                lock (_gate)
                {
                    if (active.Cancellation.IsCancellationRequested) CompleteCancellation(active);
                    else _store.Finish(binding.RequestId, DurableJobState.Failed, "JOB_EXECUTION_FAILED");
                }
            }
            return true;
        }
        finally
        {
            if (payload is not null) CryptographicOperations.ZeroMemory(payload);
            lock (_gate) { if (ReferenceEquals(_active, active)) _active = null; }
            active?.Dispose();
            _dispatch.Release();
        }
    }

    private void CompleteCancellation(ActiveJob active)
    {
        if (active.FailureCode is not null)
        { _store.Finish(active.Binding.RequestId, DurableJobState.Failed, active.FailureCode); return; }
        var expired = active.DeadlineElapsed || _clock.GetUtcNow() >= active.Binding.Deadline;
        _store.Finish(active.Binding.RequestId, expired ? DurableJobState.Expired : DurableJobState.Cancelled,
            active.CancelCode ?? (expired ? "DEADLINE_EXPIRED" : "EXECUTION_CANCELLED"));
    }
    private void CancelCore(JobBinding binding, string code)
    {
        _store.RequestCancellation(binding.RequestId, code);
        if (_active?.Binding.RequestId == binding.RequestId)
        {
            _active.CancelCode ??= code;
            _active.Cancellation.Cancel();
        }
    }
    private void RequireGrant(JobBinding binding)
    {
        if (_revokedOwners.Contains(binding.OwnerDeviceId) || _revoked.Contains((binding.OwnerDeviceId, binding.GrantId)))
            throw new JobRuntimeException("JOB_GRANT_REJECTED");
    }
    private void RequireRunning()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_executorStateUnknown) throw new JobRuntimeException("JOB_EXECUTOR_STATE_UNKNOWN");
        if (_stopping) throw new JobRuntimeException("JOB_RUNTIME_STOPPING");
        if (_authorizationCapacityExceeded) throw new JobRuntimeException("JOB_AUTHORIZATION_CAPACITY");
    }

    public async ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _stopping = true;
            if (_active is not null) CancelCore(_active.Binding, "RUNTIME_STOPPED");
            _shutdown.Cancel();
        }
        // A broken executor must not be reported stopped while its process still runs.
        if (!await _dispatch.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false))
        {
            lock (_gate)
            {
                _executorStateUnknown = true;
                if (_active is not null) _store.QuarantineExecution(_active.Binding.RequestId, "EXECUTOR_DID_NOT_STOP");
            }
            throw new JobRuntimeException("JOB_EXECUTOR_DID_NOT_STOP");
        }
        try { lock (_gate) { _disposed = true; _store.DetachRuntime(); } }
        finally { _dispatch.Release(); }
        // The caller owns the store and disposes it only after this runtime drains.
    }

    private sealed class OutputSink(DurableJobRuntime runtime, ActiveJob active) : IJobOutputSink
    {
        public ValueTask AppendAsync(ReadOnlyMemory<byte> output, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (runtime._gate)
            {
                if (runtime._clock.GetUtcNow() >= active.Binding.Deadline)
                {
                    active.CancelCode ??= "DEADLINE_EXPIRED";
                    active.Cancellation.Cancel();
                }
                active.Cancellation.Token.ThrowIfCancellationRequested();
                try { runtime._store.AppendOutput(active.Binding, output.Span); }
                catch (JobRuntimeException exception) when (exception.Code == "JOB_OUTPUT_LIMIT")
                {
                    active.FailureCode = "JOB_OUTPUT_LIMIT";
                    active.Cancellation.Cancel();
                    throw;
                }
            }
            return ValueTask.CompletedTask;
        }
    }
    private sealed class ActiveJob : IDisposable
    {
        public JobBinding Binding { get; }
        public CancellationTokenSource Cancellation { get; }
        private readonly CancellationTokenSource _deadline;
        public bool DeadlineElapsed => _deadline.IsCancellationRequested;
        public string? CancelCode { get; set; }
        public string? FailureCode { get; set; }
        public ActiveJob(JobBinding binding, CancellationToken parent, TimeSpan remaining, TimeProvider clock)
        {
            Binding = binding;
            _deadline = new CancellationTokenSource(remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero, clock);
            Cancellation = CancellationTokenSource.CreateLinkedTokenSource(parent, _deadline.Token);
        }
        public void Dispose() { Cancellation.Dispose(); _deadline.Dispose(); }
    }
}
