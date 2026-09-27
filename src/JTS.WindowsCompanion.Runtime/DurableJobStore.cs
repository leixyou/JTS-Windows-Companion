using Microsoft.Data.Sqlite;
using System.Security.Cryptography;

namespace JTS.WindowsCompanion.Runtime;

/// <summary>A single-runtime WAL ledger. The caller provisions its directory with owner-only access.</summary>
public sealed partial class DurableJobStore : IDisposable
{
    private readonly object _gate = new();
    private readonly SqliteConnection _db;
    private readonly FileStream _lease;
    private readonly ITaskPayloadProtector _protector;
    private readonly TimeProvider _clock;
    private readonly Guid _storeId;
    internal DurableJobLimits Limits { get; }
    private bool _disposed;
    private bool _runtimeAttached;

    public DurableJobStore(string databasePath, ITaskPayloadProtector protector,
        DurableJobLimits? limits = null, TimeProvider? clock = null)
        : this(databasePath, protector, limits, clock, StoreOpenMode.Existing) { }

    /// <summary>Explicit first-time local provisioning only. Never replaces an existing ledger.</summary>
    public static DurableJobStore CreateNew(string databasePath, ITaskPayloadProtector protector,
        DurableJobLimits? limits = null, TimeProvider? clock = null)
        => new(databasePath, protector, limits, clock, StoreOpenMode.CreateNew);

    /// <summary>Offline local migration only; all legacy stores require verified recovery before executing.</summary>
    public static DurableJobStore UpgradeLegacy(string databasePath, ITaskPayloadProtector protector,
        DurableJobLimits? limits = null, TimeProvider? clock = null)
        => new(databasePath, protector, limits, clock, StoreOpenMode.UpgradeLegacy);

    private enum StoreOpenMode { Existing, CreateNew, UpgradeLegacy }
    private DurableJobStore(string databasePath, ITaskPayloadProtector protector,
        DurableJobLimits? limits, TimeProvider? clock, StoreOpenMode mode)
    {
        ArgumentNullException.ThrowIfNull(protector);
        if (!Path.IsPathFullyQualified(databasePath)) throw new ArgumentException("An absolute private database path is required.");
        var path = Path.GetFullPath(databasePath);
        var parent = Path.GetDirectoryName(path)!;
        if (!Directory.Exists(parent)) throw new ArgumentException("Provision the private database directory before opening the store.");
        RejectLinks(parent); RejectLinks(path); RejectLinks(path + ".lease"); RejectLinks(path + "-wal"); RejectLinks(path + "-shm");
        if (mode != StoreOpenMode.CreateNew && !File.Exists(path)) throw new JobRuntimeException("JOB_STORE_NOT_INITIALIZED");
        Limits = limits ?? new DurableJobLimits();
        Limits.Validate();
        _protector = protector;
        _clock = clock ?? TimeProvider.System;
        _lease = new FileStream(path + ".lease", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        _db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path, Mode = SqliteOpenMode.ReadWrite, Pooling = false, DefaultTimeout = 5,
        }.ToString());
        try
        {
            if (mode == StoreOpenMode.CreateNew) using (new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None)) { }
            _db.Open();
            if (mode == StoreOpenMode.Existing) _storeId = AuthenticateSafetyHeader();
            if (mode == StoreOpenMode.UpgradeLegacy && Convert.ToInt32(Scalar("PRAGMA user_version;")) != 1)
                throw new JobRuntimeException("JOB_STORE_VERSION_UNSUPPORTED");
            Execute("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA busy_timeout=5000;");
            if (mode != StoreOpenMode.Existing) _storeId = InitializeStore(mode == StoreOpenMode.UpgradeLegacy);
            Recover();
        }
        catch { _db.Dispose(); _lease.Dispose(); throw; }
    }

    internal void ValidateSubmission(JobBinding binding)
    {
        lock (_gate)
        {
            Check();
            binding.Validate(_clock.GetUtcNow(), newSubmission: false);
            // Repeated immutable receipts remain queryable after their original deadline.
            // A new receipt must pass its deadline bound before external authorization runs.
            var previous = Find(binding.RequestId);
            if (previous is null) binding.Validate(_clock.GetUtcNow(), newSubmission: true);
            else if (previous.Binding.RequestHash != binding.RequestHash) throw new JobRuntimeException("JOB_IDEMPOTENCY_CONFLICT");
        }
    }

    internal JobSnapshot Submit(JobSubmission submission)
    {
        lock (_gate)
        {
            Check();
            var binding = submission.Binding;
            var previous = Find(binding.RequestId);
            if (previous is not null)
            {
                if (previous.Binding.RequestHash != binding.RequestHash) throw new JobRuntimeException("JOB_IDEMPOTENCY_CONFLICT");
                return previous;
            }
            binding.Validate(_clock.GetUtcNow(), newSubmission: true);
            if (submission.Payload.Length is 0 || submission.Payload.Length > Limits.MaximumPayloadBytes
                || JobBinding.Hash(submission.Payload.Span) != binding.PayloadSha256)
                throw new JobRuntimeException("JOB_PAYLOAD_INVALID");
            PruneCore();
            if (Convert.ToInt64(Scalar("SELECT COUNT(*) FROM jobs;")) >= Limits.MaximumReceiptCount)
                throw new JobRuntimeException("JOB_RECEIPT_CAPACITY");
            if (Convert.ToInt64(Scalar("SELECT COUNT(*) FROM jobs WHERE state IN (0,1,2);")) >= Limits.MaximumQueuedJobs)
                throw new JobRuntimeException("JOB_QUEUE_FULL");
            var protectedPayload = Protect(submission.Payload.Span, binding, "payload");
            using var command = Command("""
                INSERT INTO jobs(request_id,kind,owner,grant_id,deadline_ms,allow_disconnected,payload_hash,request_hash,state,submitted_ms,payload)
                VALUES($id,$kind,$owner,$grant,$deadline,$allow,$payloadHash,$requestHash,0,$now,$payload);
                """, ("$id", binding.RequestId.ToString("D")), ("$kind", binding.Kind), ("$owner", binding.OwnerDeviceId),
                ("$grant", binding.GrantId.ToString("D")), ("$deadline", binding.Deadline.ToUnixTimeMilliseconds()),
                ("$allow", binding.AllowDisconnected ? 1 : 0), ("$payloadHash", binding.PayloadSha256),
                ("$requestHash", binding.RequestHash), ("$now", _clock.GetUtcNow().ToUnixTimeMilliseconds()), ("$payload", protectedPayload));
            command.ExecuteNonQuery();
            return Find(binding.RequestId)!;
        }
    }

    public JobSnapshot Get(Guid requestId, string ownerDeviceId, Guid grantId)
    {
        lock (_gate) { Check(); return RequireOwner(requestId, ownerDeviceId, grantId); }
    }

    public byte[] ReadOutput(Guid requestId, string ownerDeviceId, Guid grantId)
    {
        lock (_gate)
        {
            Check();
            var snapshot = RequireOwner(requestId, ownerDeviceId, grantId);
            if (snapshot.DataExpired) throw new JobRuntimeException("JOB_DATA_EXPIRED");
            if (snapshot.OutputBytes == 0) return [];
            var clear = ReadProtected(snapshot.Binding, "output", Limits.MaximumOutputBytesPerJob);
            if (clear.Length != snapshot.OutputBytes) { CryptographicOperations.ZeroMemory(clear); throw new JobRuntimeException("JOB_STORE_CORRUPT"); }
            return clear;
        }
    }

    internal byte[] ReadPayload(JobBinding binding)
    {
        lock (_gate)
        {
            Check();
            var clear = ReadProtected(binding, "payload", Limits.MaximumPayloadBytes);
            if (JobBinding.Hash(clear) != binding.PayloadSha256)
            { CryptographicOperations.ZeroMemory(clear); throw new JobRuntimeException("JOB_STORE_CORRUPT"); }
            return clear;
        }
    }

    internal JobSnapshot? NextQueued()
    {
        lock (_gate)
        {
            Check();
            var id = Scalar("SELECT request_id FROM jobs WHERE state=0 ORDER BY submitted_ms,request_id LIMIT 1;");
            return id is string value ? Find(Guid.Parse(value)) : null;
        }
    }

    internal bool Start(Guid requestId)
    {
        lock (_gate)
        {
            Check();
            RequireSafetyClean();
            using var transaction = _db.BeginTransaction();
            using var command = Command("UPDATE jobs SET state=1,started_ms=$now WHERE request_id=$id AND state=0;",
                ("$id", requestId.ToString("D")), ("$now", _clock.GetUtcNow().ToUnixTimeMilliseconds()));
            command.Transaction = transaction;
            if (command.ExecuteNonQuery() != 1) return false;
            WriteSafety(new(_storeId, RuntimeSafetyState.Dispatching, Guid.NewGuid(), requestId,
                "EXECUTION_IN_FLIGHT", NowMilliseconds()), transaction);
            transaction.Commit(); // Durable uncertainty marker MUST precede any possible executor side effect.
            return true;
        }
    }

    internal void Finish(Guid requestId, DurableJobState state, string code)
    {
        if (state is DurableJobState.Queued or DurableJobState.Running or DurableJobState.Cancelling)
            throw new ArgumentException("Completion must have a terminal state.");
        if (code is not { Length: >= 1 and <= 64 } || !code.All(c => char.IsAsciiLetterOrDigit(c) || c == '_'))
            throw new JobRuntimeException("JOB_RESULT_INVALID");
        lock (_gate)
        {
            Check();
            var safety = ReadSafety();
            using var transaction = _db.BeginTransaction();
            using var command = Command("""
                UPDATE jobs SET state=$state,completed_ms=$now,result_code=$code,payload=NULL
                WHERE request_id=$id AND state IN (0,1,2);
                """, ("$state", (int)state), ("$now", _clock.GetUtcNow().ToUnixTimeMilliseconds()),
                ("$code", code), ("$id", requestId.ToString("D")));
            command.Transaction = transaction;
            command.ExecuteNonQuery();
            if (safety.State == RuntimeSafetyState.Dispatching && safety.RequestId == requestId)
            {
                WriteSafety(state == DurableJobState.Interrupted
                    ? safety with { State = RuntimeSafetyState.Quarantined, Reason = "EXECUTOR_STATE_UNKNOWN", ChangedAt = NowMilliseconds() }
                    : RuntimeSafetyRecord.Clean(_storeId, NowMilliseconds()), transaction);
            }
            transaction.Commit();
        }
    }

    internal void RequestCancellation(Guid requestId, string code)
    {
        lock (_gate)
        {
            Check();
            var snapshot = Find(requestId);
            if (snapshot?.State == DurableJobState.Queued) Finish(requestId, DurableJobState.Cancelled, code);
            else if (snapshot?.State is DurableJobState.Running or DurableJobState.Cancelling)
            {
                using var command = Command("UPDATE jobs SET state=2,result_code=$code WHERE request_id=$id AND state=1;",
                    ("$code", code), ("$id", requestId.ToString("D")));
                command.ExecuteNonQuery();
            }
        }
    }

    internal IReadOnlyList<JobSnapshot> ActiveFor(string? owner, Guid? grant, bool disconnectedOnly)
    {
        lock (_gate)
        {
            Check();
            using var command = Command("""
                SELECT request_id FROM jobs WHERE ($owner IS NULL OR owner=$owner) AND state IN (0,1,2)
                AND ($grant IS NULL OR grant_id=$grant) AND ($only=0 OR allow_disconnected=0);
                """, ("$owner", (object?)owner ?? DBNull.Value), ("$grant", (object?)grant?.ToString("D") ?? DBNull.Value), ("$only", disconnectedOnly ? 1 : 0));
            var ids = new List<Guid>();
            using (var reader = command.ExecuteReader()) while (reader.Read()) ids.Add(Guid.Parse(reader.GetString(0)));
            return ids.Select(id => Find(id)!).ToArray();
        }
    }

    internal void Recover()
    {
        lock (_gate)
        {
            Check();
            var safety = ReadSafety();
            var runningCount = Convert.ToInt64(Scalar("SELECT COUNT(*) FROM jobs WHERE state IN (1,2);"));
            // Never infer quiescence from process restart or a terminal receipt alone.
            using var transaction = _db.BeginTransaction();
            if (safety.State == RuntimeSafetyState.Dispatching || (safety.State == RuntimeSafetyState.Clean && runningCount != 0))
            {
                safety = safety with { State = RuntimeSafetyState.Quarantined,
                    IncidentId = safety.IncidentId == Guid.Empty ? Guid.NewGuid() : safety.IncidentId,
                    Reason = "RUNTIME_RESTART_INTERRUPTED", ChangedAt = NowMilliseconds() };
                WriteSafety(safety, transaction);
            }
            using var running = Command("UPDATE jobs SET state=7,completed_ms=$now,result_code='RUNTIME_RESTART_INTERRUPTED',payload=NULL WHERE state IN (1,2);",
                ("$now", _clock.GetUtcNow().ToUnixTimeMilliseconds()));
            running.Transaction = transaction; running.ExecuteNonQuery();
            using var queued = Command("UPDATE jobs SET state=5,completed_ms=$now,result_code=$code,payload=NULL WHERE state=0 AND ($unsafe=1 OR allow_disconnected=0);",
                ("$now", _clock.GetUtcNow().ToUnixTimeMilliseconds()), ("$unsafe", safety.State == RuntimeSafetyState.Quarantined ? 1 : 0),
                ("$code", safety.State == RuntimeSafetyState.Quarantined ? "EXECUTOR_STATE_UNKNOWN" : "SESSION_ENDED_ON_RESTART"));
            queued.Transaction = transaction; queued.ExecuteNonQuery();
            transaction.Commit();
            PruneCore();
        }
    }

    internal void AttachRuntime()
    {
        lock (_gate)
        {
            Check();
            if (_runtimeAttached) throw new JobRuntimeException("JOB_RUNTIME_ALREADY_ATTACHED");
            if (_recoveryInProgress) throw new JobRuntimeException("JOB_RECOVERY_IN_PROGRESS");
            Recover();
            RequireSafetyClean();
            _runtimeAttached = true;
        }
    }
    internal void DetachRuntime() { lock (_gate) _runtimeAttached = false; }

    internal void AppendOutput(JobBinding binding, ReadOnlySpan<byte> chunk)
    {
        lock (_gate)
        {
            Check();
            var snapshot = RequireOwner(binding.RequestId, binding.OwnerDeviceId, binding.GrantId);
            if (snapshot.State != DurableJobState.Running) throw new OperationCanceledException();
            if (chunk.IsEmpty) return;
            if (chunk.Length > Limits.MaximumOutputBytesPerJob - snapshot.OutputBytes
                || Convert.ToInt64(Scalar("SELECT COALESCE(SUM(output_bytes),0) FROM jobs;")) + chunk.Length > Limits.MaximumStoredOutputBytes)
                throw new JobRuntimeException("JOB_OUTPUT_LIMIT");
            var previous = snapshot.OutputBytes == 0 ? [] : ReadProtected(binding, "output", Limits.MaximumOutputBytesPerJob);
            if (previous.Length != snapshot.OutputBytes)
            { CryptographicOperations.ZeroMemory(previous); throw new JobRuntimeException("JOB_STORE_CORRUPT"); }
            var combined = new byte[previous.Length + chunk.Length];
            try
            {
                previous.CopyTo(combined, 0); chunk.CopyTo(combined.AsSpan(previous.Length));
                var cipher = Protect(combined, binding, "output");
                using var command = Command("UPDATE jobs SET output=$output,output_bytes=$bytes WHERE request_id=$id AND state=1;",
                    ("$output", cipher), ("$bytes", combined.Length), ("$id", binding.RequestId.ToString("D")));
                command.ExecuteNonQuery();
            }
            finally { CryptographicOperations.ZeroMemory(previous); CryptographicOperations.ZeroMemory(combined); }
        }
    }

    public void PruneExpiredData() { lock (_gate) { Check(); PruneCore(); } }
    private void PruneCore()
    {
        using var command = Command("""
            UPDATE jobs SET payload=NULL,output=NULL,output_bytes=0,data_expired=1
            WHERE completed_ms IS NOT NULL AND completed_ms <= $cutoff AND data_expired=0;
            """, ("$cutoff", (_clock.GetUtcNow() - Limits.DataRetention).ToUnixTimeMilliseconds()));
        command.ExecuteNonQuery(); // Immutable receipts remain; capacity exhaustion fails closed, never permits replay.
    }

    private byte[] Protect(ReadOnlySpan<byte> clear, JobBinding binding, string purpose)
    {
        var cipher = _protector.Protect(clear, binding.ProtectionContext(purpose));
        if (cipher is null || cipher.Length == 0 || cipher.Length > clear.Length + 4096)
            throw new JobRuntimeException("JOB_PROTECTOR_INVALID");
        return cipher;
    }
    private byte[] ReadProtected(JobBinding binding, string column, int maximum)
    {
        using var command = Command($"SELECT {column},length({column}) FROM jobs WHERE request_id=$id;", ("$id", binding.RequestId.ToString("D")));
        using var reader = command.ExecuteReader();
        if (!reader.Read() || reader.IsDBNull(0) || reader.GetInt64(1) > maximum + 4096)
            throw new JobRuntimeException("JOB_STORE_CORRUPT");
        var cipher = (byte[])reader.GetValue(0);
        byte[] clear;
        try { clear = _protector.Unprotect(cipher, binding.ProtectionContext(column)); }
        catch (CryptographicException) { throw new JobRuntimeException("JOB_PAYLOAD_AUTHENTICATION_FAILED"); }
        if (clear is null || clear.Length > maximum)
        { if (clear is not null) CryptographicOperations.ZeroMemory(clear); throw new JobRuntimeException("JOB_STORE_CORRUPT"); }
        return clear;
    }

    private JobSnapshot RequireOwner(Guid id, string owner, Guid grant)
    {
        var snapshot = Find(id);
        if (snapshot is null || snapshot.Binding.OwnerDeviceId != owner || snapshot.Binding.GrantId != grant)
            throw new JobRuntimeException("JOB_NOT_FOUND");
        return snapshot;
    }
    private JobSnapshot? Find(Guid id)
    {
        using var command = Command("""
            SELECT kind,owner,grant_id,deadline_ms,allow_disconnected,payload_hash,request_hash,state,
            submitted_ms,started_ms,completed_ms,result_code,output_bytes,data_expired FROM jobs WHERE request_id=$id;
            """, ("$id", id.ToString("D")));
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        var binding = new JobBinding(id, reader.GetString(0), reader.GetString(1), Guid.Parse(reader.GetString(2)),
            DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(3)), reader.GetBoolean(4), reader.GetString(5));
        binding.Validate(_clock.GetUtcNow(), newSubmission: false);
        if (binding.RequestHash != reader.GetString(6) || !Enum.IsDefined((DurableJobState)reader.GetInt32(7)))
            throw new JobRuntimeException("JOB_STORE_CORRUPT");
        return new JobSnapshot(binding, (DurableJobState)reader.GetInt32(7),
            DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(8)), Time(9), Time(10),
            reader.IsDBNull(11) ? null : reader.GetString(11), reader.GetInt32(12), reader.GetBoolean(13));
        DateTimeOffset? Time(int ordinal) => reader.IsDBNull(ordinal) ? null : DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(ordinal));
    }
    private SqliteCommand Command(string sql, params (string Name, object Value)[] arguments)
    {
        var command = _db.CreateCommand(); command.CommandText = sql;
        foreach (var argument in arguments) command.Parameters.AddWithValue(argument.Name, argument.Value);
        return command;
    }
    private object? Scalar(string sql) { using var command = Command(sql); return command.ExecuteScalar(); }
    private void Execute(string sql) { using var command = Command(sql); command.ExecuteNonQuery(); }
    private void Check() => ObjectDisposedException.ThrowIf(_disposed, this);
    private static void RejectLinks(string path)
    {
        var current = path;
        do
        {
            if (new FileInfo(current).LinkTarget is not null
                || ((File.Exists(current) || Directory.Exists(current)) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0))
                throw new ArgumentException("The job database path cannot traverse a reparse point.");
            current = OperatingSystem.IsWindows() ? Path.GetDirectoryName(current) : null;
        } while (!string.IsNullOrEmpty(current));
    }
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            if (_runtimeAttached) throw new JobRuntimeException("JOB_RUNTIME_STILL_ATTACHED");
            if (_recoveryInProgress) throw new JobRuntimeException("JOB_RECOVERY_IN_PROGRESS");
            _disposed = true; _db.Dispose(); _lease.Dispose();
        }
    }
}
