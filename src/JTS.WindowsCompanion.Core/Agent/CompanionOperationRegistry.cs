using JTS.WindowsCompanion.Protocol;

namespace JTS.WindowsCompanion.Agent;

internal enum CompanionOperationCancellationReason
{
    None = 0,
    RequestCancelled = 1,
    DeadlineExceeded = 2,
    ConnectionClosed = 3,
    PeerUnpaired = 4,
}

/// Tracks only operations owned by a verified, frame-authenticated peer session.
/// Owner keys are derived inside the Companion from the live session binding and
/// verified peer public key; no caller-supplied identity participates.
internal sealed class CompanionOperationRegistry
{
    private static readonly TimeSpan MaximumTimerInterval = TimeSpan.FromDays(24);

    private readonly object _sync = new();
    private readonly Dictionary<Guid, ActiveOperation> _active = [];
    private readonly HashSet<string> _blockedOwners = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;

    public CompanionOperationRegistry(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public int ActiveCount
    {
        get
        {
            lock (_sync)
            {
                return _active.Count;
            }
        }
    }

    public CompanionOperationLease Register(
        Guid requestId,
        string ownerKey,
        long? deadlineUnixMilliseconds,
        CancellationToken connectionCancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ownerKey);
        if (requestId == Guid.Empty)
        {
            throw new ArgumentException("An operation request ID is required.", nameof(requestId));
        }

        var operation = new ActiveOperation(
            requestId,
            ownerKey,
            deadlineUnixMilliseconds,
            connectionCancellationToken,
            _timeProvider);
        lock (_sync)
        {
            if (_blockedOwners.Contains(ownerKey))
            {
                operation.Dispose();
                throw new CompanionProtocolException(
                    "REQUEST_CANCELLED",
                    "The authenticated peer session is being revoked.");
            }

            if (!_active.TryAdd(requestId, operation))
            {
                operation.Dispose();
                throw new CompanionProtocolException(
                    "REQUEST_ALREADY_ACTIVE",
                    "The request ID is already active.");
            }
        }

        operation.StartDeadline();
        return new CompanionOperationLease(this, operation);
    }

    public bool Cancel(string ownerKey, Guid requestId)
    {
        ActiveOperation? operation;
        lock (_sync)
        {
            _active.TryGetValue(requestId, out operation);
            if (operation is null || !operation.IsOwnedBy(ownerKey))
            {
                return false;
            }
        }

        operation.Cancel(CompanionOperationCancellationReason.RequestCancelled);
        return true;
    }

    public async ValueTask<int> CancelOwnerAndDrainAsync(
        string ownerKey,
        CompanionOperationCancellationReason reason,
        Guid? excludingRequestId,
        CancellationToken cancellationToken)
    {
        var operations = Snapshot(ownerKey, excludingRequestId);
        foreach (var operation in operations)
        {
            operation.Cancel(reason);
        }

        await DrainAsync(operations, cancellationToken).ConfigureAwait(false);
        return operations.Length;
    }

    public async ValueTask<CompanionOwnerOperationBlock> BlockOwnerAndDrainAsync(
        string ownerKey,
        Guid excludingRequestId,
        CancellationToken cancellationToken)
    {
        ActiveOperation[] operations;
        lock (_sync)
        {
            _blockedOwners.Add(ownerKey);
            operations = _active.Values
                .Where(operation => operation.IsOwnedBy(ownerKey)
                    && operation.RequestId != excludingRequestId)
                .ToArray();
        }

        foreach (var operation in operations)
        {
            operation.Cancel(CompanionOperationCancellationReason.PeerUnpaired);
        }

        try
        {
            await DrainAsync(operations, cancellationToken).ConfigureAwait(false);
            return new CompanionOwnerOperationBlock(this, ownerKey);
        }
        catch
        {
            Unblock(ownerKey);
            throw;
        }
    }

    public async ValueTask CancelAllAndDrainAsync(CancellationToken cancellationToken)
    {
        ActiveOperation[] operations;
        lock (_sync)
        {
            operations = _active.Values.ToArray();
        }

        foreach (var operation in operations)
        {
            operation.Cancel(CompanionOperationCancellationReason.ConnectionClosed);
        }

        await DrainAsync(operations, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask DrainAsync(
        IReadOnlyList<ActiveOperation> operations,
        CancellationToken cancellationToken)
    {
        if (operations.Count == 0)
        {
            return;
        }

        await Task.WhenAll(operations.Select(operation => operation.Completion))
            .WaitAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private ActiveOperation[] Snapshot(string ownerKey, Guid? excludingRequestId)
    {
        lock (_sync)
        {
            return _active.Values
                .Where(operation => operation.IsOwnedBy(ownerKey)
                    && operation.RequestId != excludingRequestId)
                .ToArray();
        }
    }

    private void Complete(ActiveOperation operation)
    {
        lock (_sync)
        {
            if (_active.TryGetValue(operation.RequestId, out var current)
                && ReferenceEquals(current, operation))
            {
                _active.Remove(operation.RequestId);
            }
        }

        operation.Complete();
    }

    private void Unblock(string ownerKey)
    {
        lock (_sync)
        {
            _blockedOwners.Remove(ownerKey);
        }
    }

    internal sealed class CompanionOperationLease : IDisposable
    {
        private CompanionOperationRegistry? _registry;
        private ActiveOperation? _operation;

        internal CompanionOperationLease(
            CompanionOperationRegistry registry,
            ActiveOperation operation)
        {
            _registry = registry;
            _operation = operation;
        }

        public CancellationToken CancellationToken =>
            _operation?.CancellationToken ?? new CancellationToken(canceled: true);

        public CompanionOperationCancellationReason CancellationReason =>
            _operation?.CancellationReason ?? CompanionOperationCancellationReason.ConnectionClosed;

        public void Dispose()
        {
            var operation = Interlocked.Exchange(ref _operation, null);
            var registry = Interlocked.Exchange(ref _registry, null);
            if (operation is not null && registry is not null)
            {
                registry.Complete(operation);
            }
        }
    }

    internal sealed class CompanionOwnerOperationBlock : IDisposable
    {
        private CompanionOperationRegistry? _registry;
        private readonly string _ownerKey;

        public CompanionOwnerOperationBlock(
            CompanionOperationRegistry registry,
            string ownerKey)
        {
            _registry = registry;
            _ownerKey = ownerKey;
        }

        public void Dispose()
        {
            Interlocked.Exchange(ref _registry, null)?.Unblock(_ownerKey);
        }
    }

    internal sealed class ActiveOperation : IDisposable
    {
        private readonly string _ownerKey;
        private readonly long? _deadlineUnixMilliseconds;
        private readonly CancellationTokenSource _cancellation;
        private readonly CancellationTokenRegistration _connectionCancellationRegistration;
        private readonly TimeProvider _timeProvider;
        private readonly TaskCompletionSource _completion =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private ITimer? _deadlineTimer;
        private int _cancellationReason;
        private int _completed;

        public ActiveOperation(
            Guid requestId,
            string ownerKey,
            long? deadlineUnixMilliseconds,
            CancellationToken connectionCancellationToken,
            TimeProvider timeProvider)
        {
            RequestId = requestId;
            _ownerKey = ownerKey;
            _deadlineUnixMilliseconds = deadlineUnixMilliseconds;
            _timeProvider = timeProvider;
            _cancellation = CancellationTokenSource.CreateLinkedTokenSource(
                connectionCancellationToken);
            _connectionCancellationRegistration = connectionCancellationToken.Register(
                static state => ((ActiveOperation)state!).Cancel(
                    CompanionOperationCancellationReason.ConnectionClosed),
                this);
        }

        public Guid RequestId { get; }

        public CancellationToken CancellationToken => _cancellation.Token;

        public CompanionOperationCancellationReason CancellationReason =>
            (CompanionOperationCancellationReason)Volatile.Read(ref _cancellationReason);

        public Task Completion => _completion.Task;

        public bool IsOwnedBy(string ownerKey) =>
            string.Equals(_ownerKey, ownerKey, StringComparison.Ordinal);

        public void StartDeadline()
        {
            if (_deadlineUnixMilliseconds is null || CancellationReason != CompanionOperationCancellationReason.None)
            {
                return;
            }

            ScheduleDeadlineTimer();
        }

        public void Cancel(CompanionOperationCancellationReason reason)
        {
            if (reason == CompanionOperationCancellationReason.None
                || Interlocked.CompareExchange(
                    ref _cancellationReason,
                    (int)reason,
                    (int)CompanionOperationCancellationReason.None)
                    != (int)CompanionOperationCancellationReason.None)
            {
                return;
            }

            try
            {
                _cancellation.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // Completion won the race; no operation remains to cancel.
            }
        }

        public void Complete()
        {
            if (Interlocked.Exchange(ref _completed, 1) != 0)
            {
                return;
            }

            _completion.TrySetResult();
            Dispose();
        }

        public void Dispose()
        {
            Interlocked.Exchange(ref _deadlineTimer, null)?.Dispose();
            _connectionCancellationRegistration.Dispose();
            _cancellation.Dispose();
        }

        private void ScheduleDeadlineTimer()
        {
            var remaining = RemainingUntilDeadline();
            if (remaining <= TimeSpan.Zero)
            {
                Cancel(CompanionOperationCancellationReason.DeadlineExceeded);
                return;
            }

            var dueTime = remaining < MaximumTimerInterval
                ? remaining
                : MaximumTimerInterval;
            var timer = Volatile.Read(ref _deadlineTimer);
            if (timer is not null)
            {
                timer.Change(dueTime, Timeout.InfiniteTimeSpan);
                return;
            }

            var created = _timeProvider.CreateTimer(
                static state => ((ActiveOperation)state!).DeadlineTimerFired(),
                this,
                dueTime,
                Timeout.InfiniteTimeSpan);
            timer = Interlocked.CompareExchange(ref _deadlineTimer, created, null);
            if (timer is not null)
            {
                created.Dispose();
                timer.Change(dueTime, Timeout.InfiniteTimeSpan);
            }
        }

        private void DeadlineTimerFired()
        {
            if (CancellationReason != CompanionOperationCancellationReason.None)
            {
                return;
            }

            if (RemainingUntilDeadline() <= TimeSpan.Zero)
            {
                Cancel(CompanionOperationCancellationReason.DeadlineExceeded);
                return;
            }

            ScheduleDeadlineTimer();
        }

        private TimeSpan RemainingUntilDeadline()
        {
            var now = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
            var deadline = _deadlineUnixMilliseconds ?? now;
            if (deadline <= now)
            {
                return TimeSpan.Zero;
            }

            var maximumMilliseconds = (long)MaximumTimerInterval.TotalMilliseconds;
            if (now > long.MaxValue - maximumMilliseconds
                || deadline > now + maximumMilliseconds)
            {
                return MaximumTimerInterval;
            }

            var milliseconds = deadline - now;
            return TimeSpan.FromMilliseconds(milliseconds);
        }
    }
}
