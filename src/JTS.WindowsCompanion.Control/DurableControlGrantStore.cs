using Microsoft.Data.Sqlite;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.Control;

/// <summary>Private local authority state, never writable through remote RPC. No implicit initialization or approval.</summary>
public sealed partial class DurableControlGrantStore : IDurableControlGrantProvider, IDisposable
{
    private readonly object _gate = new();
    private readonly SqliteConnection _db;
    private readonly FileStream _lease;
    private readonly ITaskPayloadProtector _protector;
    private readonly TimeProvider _clock;
    private readonly int _maximumRecords;
    private readonly Guid _storeId;
    private bool _disposed;

    public DurableControlGrantStore(string databasePath, ITaskPayloadProtector protector,
        int maximumRecords = 4096, TimeProvider? clock = null)
        : this(databasePath, protector, maximumRecords, clock, createNew: false) { }

    /// <summary>Explicit first-time local setup only. Existing/missing/corrupt stores are never silently replaced.</summary>
    public static DurableControlGrantStore CreateNew(string databasePath, ITaskPayloadProtector protector,
        int maximumRecords = 4096, TimeProvider? clock = null) => new(databasePath, protector, maximumRecords, clock, createNew: true);

    private DurableControlGrantStore(string databasePath, ITaskPayloadProtector protector,
        int maximumRecords, TimeProvider? clock, bool createNew)
    {
        ArgumentNullException.ThrowIfNull(protector);
        if (maximumRecords is < 1 or > 16384) throw new ArgumentOutOfRangeException(nameof(maximumRecords));
        var path = ValidatePath(databasePath);
        if (!createNew && !File.Exists(path)) throw new ControlPolicyException("CONTROL_POLICY_NOT_INITIALIZED");
        _protector = protector; _clock = clock ?? TimeProvider.System; _maximumRecords = maximumRecords;
        _lease = new(path + ".lease", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        _db = new(new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadWrite,
            Pooling = false, DefaultTimeout = 5 }.ToString());
        try
        {
            if (createNew) using (new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None)) { }
            _db.Open();
            // Validate an existing authority before changing its journal settings or schema.
            if (!createNew) _storeId = AuthenticateHeader();
            Execute("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; PRAGMA secure_delete=ON;");
            Execute("PRAGMA max_page_count=65536; PRAGMA journal_size_limit=1048576;");
            if (createNew) _storeId = Initialize();
            if (Convert.ToInt64(Scalar("SELECT count(*) FROM control_grants;")) > _maximumRecords)
                throw new ControlPolicyException("CONTROL_POLICY_CAPACITY");
        }
        catch { _db.Dispose(); _lease.Dispose(); throw; }
    }

    /// <summary>Call only after local Windows consent and separately verified device pairing. Never expose over control RPC.</summary>
    public ControlPolicyRecord ApproveLocally(ControlGrant grant)
    {
        ArgumentNullException.ThrowIfNull(grant);
        lock (_gate)
        {
            Check();
            var existing = Read(grant.GrantId);
            if (existing is not null)
            {
                if (existing.RevokedAt is null && existing.Grant is not null && ControlPolicyCodec.SameGrant(existing.Grant, grant))
                    return existing;
                throw new ControlPolicyException("CONTROL_POLICY_GRANT_CONFLICT");
            }
            if (grant.ExpiresAt <= _clock.GetUtcNow()) throw new ControlPolicyException("CONTROL_POLICY_GRANT_EXPIRED");
            RequireCapacity();
            var record = new ControlPolicyRecord(grant.OwnerDeviceId, grant.GrantId, grant, Now(), null);
            Write(record, insert: true); return record;
        }
    }

    public ValueTask<ControlGrant?> FindAsync(string authenticatedOwner, Guid grantId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); ControlPolicyCodec.Identity(authenticatedOwner, grantId);
        lock (_gate)
        {
            Check(); cancellationToken.ThrowIfCancellationRequested();
            var record = Read(grantId);
            var grant = record?.OwnerDeviceId == authenticatedOwner && record.RevokedAt is null ? record.Grant : null;
            var now = _clock.GetUtcNow();
            return ValueTask.FromResult(record?.ApprovedAt <= now && grant?.ExpiresAt > now ? grant : null);
        }
    }

    public ValueTask RevokeAsync(string ownerDeviceId, Guid grantId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); ControlPolicyCodec.Identity(ownerDeviceId, grantId);
        lock (_gate)
        {
            Check(); cancellationToken.ThrowIfCancellationRequested();
            var record = Read(grantId);
            if (record is not null && record.OwnerDeviceId != ownerDeviceId)
                throw new ControlPolicyException("CONTROL_POLICY_GRANT_CONFLICT");
            if (record?.RevokedAt is not null) return ValueTask.CompletedTask;
            if (record is null) RequireCapacity();
            var revoked = record is null ? new(ownerDeviceId, grantId, null, null, Now()) : record with { RevokedAt = Now() };
            Write(revoked, insert: record is null);
            // Do not throw cancellation after the commit: the host must run its immediate cancellation hook.
            return ValueTask.CompletedTask;
        }
    }

    /// <summary>Bounded local consent-management inventory, not a remote operation or authentication decision.</summary>
    public IReadOnlyList<ControlPolicyRecord> ListLocally()
    {
        lock (_gate)
        {
            Check(); var ids = new List<Guid>();
            using (var command = Command("SELECT grant_id FROM control_grants ORDER BY grant_id LIMIT $limit;", ("$limit", _maximumRecords + 1)))
            using (var reader = command.ExecuteReader())
                while (reader.Read()) ids.Add(ParseId(reader.GetString(0)));
            if (ids.Count > _maximumRecords) throw new ControlPolicyException("CONTROL_POLICY_CAPACITY");
            return ids.Select(id => Read(id) ?? throw ControlPolicyCodec.Invalid()).ToArray();
        }
    }

    private void RequireCapacity()
    {
        if (Convert.ToInt64(Scalar("SELECT count(*) FROM control_grants;")) >= _maximumRecords)
            throw new ControlPolicyException("CONTROL_POLICY_CAPACITY");
    }
    private DateTimeOffset Now() => DateTimeOffset.FromUnixTimeMilliseconds(_clock.GetUtcNow().ToUnixTimeMilliseconds());
    private void Check() => ObjectDisposedException.ThrowIf(_disposed, this);
    public void Dispose()
    {
        lock (_gate) { if (_disposed) return; _disposed = true; _db.Dispose(); _lease.Dispose(); }
    }
}
