using System.Security.Cryptography;
using System.Text;

namespace JTS.WindowsCompanion.Elevation;

public enum ElevatedActionKind
{
    ApprovedPowerShell,
    FileMutation,
    WorkerOperation,
}

public sealed record ElevatedActionGrant(
    string ActionId,
    ElevatedActionKind Kind,
    string PayloadSha256,
    string DisplaySummary);

public sealed record ElevationLeaseRequest(
    Guid RequestId,
    TimeSpan Duration,
    IReadOnlyList<ElevatedActionGrant> Actions);

public sealed record ElevationLease(
    Guid LeaseId,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    IReadOnlyList<ElevatedActionGrant> Actions);

public sealed class ElevationLeaseManager : IDisposable
{
    public static readonly TimeSpan MaximumDuration = TimeSpan.FromMinutes(15);
    private readonly TimeProvider _timeProvider;
    private readonly Dictionary<Guid, LeaseRegistration> _leases = new();
    private readonly object _sync = new();
    private bool _disposed;

    public ElevationLeaseManager(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public int ActiveLeaseCount
    {
        get
        {
            LeaseRegistration[] expired;
            int count;
            lock (_sync)
            {
                ThrowIfDisposed();
                expired = RemoveExpired(_timeProvider.GetUtcNow());
                count = _leases.Count;
            }

            CancelAll(expired);
            return count;
        }
    }

    public ElevationLease IssueApproved(ElevationLeaseRequest request, bool userConfirmedOnSecureDesktop)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!userConfirmedOnSecureDesktop)
        {
            throw new UnauthorizedAccessException("Elevation requires explicit Windows user confirmation.");
        }

        if (request.RequestId == Guid.Empty
            || request.Duration <= TimeSpan.Zero
            || request.Duration > MaximumDuration
            || request.Actions.Count == 0
            || request.Actions.Count > 32)
        {
            throw new ArgumentException("The elevation request is outside the permitted bounds.", nameof(request));
        }

        foreach (var action in request.Actions)
        {
            if (string.IsNullOrWhiteSpace(action.ActionId)
                || action.ActionId.Length > 128
                || action.DisplaySummary.Length is < 1 or > 512
                || !IsSha256(action.PayloadSha256))
            {
                throw new ArgumentException("Every elevated action must have an ID, display summary, and payload digest.", nameof(request));
            }
        }

        if (request.Actions.Select(action => action.ActionId).Distinct(StringComparer.Ordinal).Count() != request.Actions.Count)
        {
            throw new ArgumentException("Every elevated action ID must be unique within a lease.", nameof(request));
        }

        var now = _timeProvider.GetUtcNow();
        var lease = new ElevationLease(Guid.NewGuid(), now, now + request.Duration, request.Actions.ToArray());
        LeaseRegistration registration;
        LeaseRegistration[] expired;
        lock (_sync)
        {
            ThrowIfDisposed();
            expired = RemoveExpired(now);
            registration = new LeaseRegistration(lease);
            _leases.Add(lease.LeaseId, registration);
        }

        CancelAll(expired);

        try
        {
            registration.SetExpirationTimer(_timeProvider.CreateTimer(
                static state =>
                {
                    var expiration = (LeaseExpiration)state!;
                    expiration.Manager.Expire(expiration.LeaseId, expiration.Registration);
                },
                new LeaseExpiration(this, lease.LeaseId, registration),
                request.Duration,
                Timeout.InfiniteTimeSpan));
        }
        catch
        {
            Expire(lease.LeaseId, registration);
            throw;
        }

        return lease;
    }

    public CancellationToken Authorize(
        Guid leaseId,
        string actionId,
        ElevatedActionKind kind,
        ReadOnlySpan<byte> payload)
    {
        var digest = Convert.ToHexString(SHA256.HashData(payload));
        LeaseRegistration[] expired;
        LeaseRegistration? registration;
        lock (_sync)
        {
            ThrowIfDisposed();
            var now = _timeProvider.GetUtcNow();
            expired = RemoveExpired(now);
            _leases.TryGetValue(leaseId, out registration);
        }

        CancelAll(expired);
        if (registration is null)
        {
            throw new UnauthorizedAccessException("The elevation lease is missing or expired.");
        }

        var action = registration.Lease.Actions.SingleOrDefault(candidate =>
            candidate.ActionId == actionId && candidate.Kind == kind);
        if (action is null
            || !CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(action.PayloadSha256.ToUpperInvariant()),
                Encoding.ASCII.GetBytes(digest)))
        {
            throw new UnauthorizedAccessException("The elevated action is not covered by this lease.");
        }

        return registration.CancellationToken;
    }

    public ElevationLease GetStatus(Guid leaseId)
    {
        LeaseRegistration[] expired;
        LeaseRegistration? registration;
        lock (_sync)
        {
            ThrowIfDisposed();
            expired = RemoveExpired(_timeProvider.GetUtcNow());
            _leases.TryGetValue(leaseId, out registration);
        }

        CancelAll(expired);
        return registration?.Lease
            ?? throw new KeyNotFoundException("The elevation lease was not found.");
    }

    public void Revoke(Guid leaseId)
    {
        LeaseRegistration? registration;
        lock (_sync)
        {
            ThrowIfDisposed();
            _leases.Remove(leaseId, out registration);
        }

        registration?.CancelAndDispose();
    }

    private LeaseRegistration[] RemoveExpired(DateTimeOffset now)
    {
        var expired = _leases.Values
            .Where(candidate => candidate.Lease.ExpiresAt <= now)
            .ToArray();
        foreach (var registration in expired)
        {
            _leases.Remove(registration.Lease.LeaseId);
        }

        return expired;
    }

    private void Expire(Guid leaseId, LeaseRegistration expected)
    {
        LeaseRegistration? registration = null;
        lock (_sync)
        {
            if (!_disposed
                && _leases.TryGetValue(leaseId, out var current)
                && ReferenceEquals(current, expected))
            {
                _leases.Remove(leaseId);
                registration = current;
            }
        }

        registration?.CancelAndDispose();
    }

    public void Dispose()
    {
        LeaseRegistration[] registrations;
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            registrations = _leases.Values.ToArray();
            _leases.Clear();
        }

        foreach (var registration in registrations)
        {
            registration.CancelAndDispose();
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    private static void CancelAll(IEnumerable<LeaseRegistration> registrations)
    {
        foreach (var registration in registrations)
        {
            registration.CancelAndDispose();
        }
    }

    private static bool IsSha256(string value) =>
        value.Length == 64 && value.All(character => char.IsAsciiHexDigit(character));

    private sealed class LeaseRegistration
    {
        private readonly CancellationTokenSource _cancellation = new();
        private readonly CancellationToken _cancellationToken;
        private ITimer? _expirationTimer;
        private int _disposed;

        public LeaseRegistration(ElevationLease lease)
        {
            Lease = lease;
            _cancellationToken = _cancellation.Token;
        }

        public ElevationLease Lease { get; }

        public CancellationToken CancellationToken => _cancellationToken;

        public void SetExpirationTimer(ITimer timer)
        {
            ArgumentNullException.ThrowIfNull(timer);
            if (Interlocked.CompareExchange(ref _expirationTimer, timer, null) is not null)
            {
                timer.Dispose();
                throw new InvalidOperationException("The elevation lease expiration timer was already configured.");
            }

            if (Volatile.Read(ref _disposed) != 0)
            {
                Interlocked.Exchange(ref _expirationTimer, null)?.Dispose();
            }
        }

        public void CancelAndDispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            try
            {
                _cancellation.Cancel();
            }
            catch (AggregateException)
            {
                // Cancellation callbacks are untrusted observers. Every callback is
                // attempted, and their failures must not keep a lease alive.
            }
            finally
            {
                Interlocked.Exchange(ref _expirationTimer, null)?.Dispose();
                _cancellation.Dispose();
            }
        }
    }

    private sealed record LeaseExpiration(
        ElevationLeaseManager Manager,
        Guid LeaseId,
        LeaseRegistration Registration);
}
