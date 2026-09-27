using Microsoft.Data.Sqlite;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.Pairing;

/// <summary>Protected authority-owned pairing registry. Explicit local enrollment only, with permanent epoch tombstones.</summary>
public sealed partial class DurableRelayPairingStore : IDisposable
{
    private readonly object _gate = new();
    private readonly SqliteConnection _db;
    private readonly FileStream _lease;
    private readonly ITaskPayloadProtector _protector;
    private readonly TimeProvider _clock;
    private readonly int _capacity;
    private readonly Guid _storeId;
    private bool _disposed;
    public string LocalDeviceId { get; }

    public DurableRelayPairingStore(string path, string localDeviceId, ITaskPayloadProtector protector,
        int maximumRecords = 256, TimeProvider? clock = null) : this(path, localDeviceId, protector, maximumRecords, clock, false) { }
    public static DurableRelayPairingStore CreateNew(string path, string localDeviceId, ITaskPayloadProtector protector,
        int maximumRecords = 256, TimeProvider? clock = null) => new(path, localDeviceId, protector, maximumRecords, clock, true);

    private DurableRelayPairingStore(string path, string localDeviceId, ITaskPayloadProtector protector,
        int capacity, TimeProvider? clock, bool createNew)
    {
        ArgumentNullException.ThrowIfNull(protector); PairingValidation.Device(localDeviceId);
        if (capacity is < 1 or > 4096) throw new ArgumentOutOfRangeException(nameof(capacity));
        path = PairingStorePath.Validate(path);
        if (!createNew && !File.Exists(path)) throw new PairingStoreException("PAIRING_STORE_NOT_INITIALIZED");
        LocalDeviceId = localDeviceId; _protector = protector; _clock = clock ?? TimeProvider.System; _capacity = capacity;
        _lease = new(path + ".lease", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        _db = new(new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadWrite, Pooling = false, DefaultTimeout = 5 }.ToString());
        try
        {
            if (createNew) using (new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None)) { }
            _db.Open();
            if (!createNew) _storeId = AuthenticateHeader();
            Execute("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; PRAGMA secure_delete=ON;");
            Execute("PRAGMA max_page_count=65536; PRAGMA journal_size_limit=1048576;");
            if (createNew) _storeId = Initialize();
            if (Count() > _capacity) throw new PairingStoreException("PAIRING_STORE_CAPACITY");
        }
        catch { _db.Dispose(); _lease.Dispose(); throw; }
    }

    /// <summary>Trusted local Windows consent path only. The caller must actually compare the displayed peer fingerprint.</summary>
    public RelayPairingRecord ApproveLocally(RelayDevicePairing policy, string verifiedPeerFingerprint)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (policy.ControllerDeviceId == LocalDeviceId || verifiedPeerFingerprint != policy.ControllerDeviceId)
            throw new PairingStoreException("PAIRING_CONFIRMATION_MISMATCH");
        lock (_gate)
        {
            Check(); var existing = Read(policy.PairingId);
            if (existing is not null)
            {
                if (existing.RevokedAt is null && existing.Policy?.SamePolicy(policy) == true) return existing;
                throw new PairingStoreException("PAIRING_EPOCH_CONFLICT");
            }
            if (policy.ExpiresAt <= Now()) throw new PairingStoreException("PAIRING_EXPIRED");
            if (Current(policy.ControllerDeviceId) is not null) throw new PairingStoreException("PAIRING_PEER_ALREADY_PAIRED");
            RequireCapacity();
            var record = new RelayPairingRecord(policy.ControllerDeviceId, policy.PairingId, policy, Now(), null);
            Write(record, true); return record;
        }
    }

    /// <summary>Explicit owner-delegated local installation. Never accepts relay admission as authority.</summary>
    public RelayPairingRecord ApproveDelegatedInstallation(RelayDelegatedEnrollment enrollment)
    {
        ArgumentNullException.ThrowIfNull(enrollment); enrollment.RequireCurrent(_clock);
        return ApproveLocally(enrollment.Pairing(), enrollment.ControllerDeviceID);
    }

    public ValueTask<RelayDevicePairing?> FindAsync(string controllerDeviceId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested(); PairingValidation.Device(controllerDeviceId);
        lock (_gate)
        {
            Check(); cancellationToken.ThrowIfCancellationRequested();
            var current = Current(controllerDeviceId); var now = Now();
            return ValueTask.FromResult(current?.ApprovedAt <= now && current.Policy?.ExpiresAt > now ? current.Policy : null);
        }
    }

    public ValueTask RevokeAsync(string controllerDeviceId, Guid pairingId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested(); PairingValidation.Identity(controllerDeviceId, pairingId);
        if (controllerDeviceId == LocalDeviceId) throw new PairingStoreException("PAIRING_CONFIRMATION_MISMATCH");
        lock (_gate)
        {
            Check(); cancellationToken.ThrowIfCancellationRequested();
            var current = Current(controllerDeviceId); var record = Read(pairingId);
            if ((current is not null && current.PairingId != pairingId) || (record is not null && record.ControllerDeviceId != controllerDeviceId))
                throw new PairingStoreException("PAIRING_EPOCH_CONFLICT");
            if (record?.RevokedAt is not null) return ValueTask.CompletedTask;
            if (record is null) RequireCapacity();
            var revoked = record is null ? new(controllerDeviceId, pairingId, null, null, Now()) : record with { RevokedAt = Now() };
            Write(revoked, record is null);
            return ValueTask.CompletedTask; // Never throw cancellation after durable commit; live revocation must follow.
        }
    }

    /// <summary>Bounded local-management page, never a remote operation or an authorization result.</summary>
    public IReadOnlyList<RelayPairingRecord> ListLocally(int offset = 0, int count = 64)
    {
        if (offset is < 0 or > 4096 || count is < 1 or > 64) throw new ArgumentOutOfRangeException(nameof(count));
        lock (_gate)
        {
            Check(); var ids = new List<Guid>();
            using (var command = Command("SELECT pairing_id FROM relay_pairings ORDER BY pairing_id LIMIT $count OFFSET $offset;", ("$count", count), ("$offset", offset)))
            using (var reader = command.ExecuteReader()) while (reader.Read()) ids.Add(ParseId(reader.GetString(0)));
            return ids.Select(id => Read(id) ?? throw PairingValidation.Invalid()).ToArray();
        }
    }

    private long Count() => Convert.ToInt64(Scalar("SELECT count(*) FROM relay_pairings;"));
    private void RequireCapacity() { if (Count() >= _capacity) throw new PairingStoreException("PAIRING_STORE_CAPACITY"); }
    private DateTimeOffset Now() => DateTimeOffset.FromUnixTimeMilliseconds(_clock.GetUtcNow().ToUnixTimeMilliseconds());
    private void Check() => ObjectDisposedException.ThrowIf(_disposed, this);
    public void Dispose() { lock (_gate) { if (_disposed) return; _disposed = true; _db.Dispose(); _lease.Dispose(); } }
}
