using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace JTS.WindowsCompanion.Runtime;

public sealed partial class DurableJobStore
{
    private static readonly byte[] SafetyHeaderPurpose = Encoding.UTF8.GetBytes("JTS-JOB-SAFETY-V1/header");

    private Guid InitializeStore(bool legacy)
    {
        if (legacy) ValidateLegacyReceipts();
        var id = Guid.NewGuid();
        var clear = SafetyHeader(id);
        byte[] cipher;
        try { cipher = _protector.Protect(clear, SafetyHeaderPurpose); }
        finally { CryptographicOperations.ZeroMemory(clear); }
        if (cipher is not { Length: > 0 and <= RuntimeSafetyCodec.MaximumCiphertext }) throw RuntimeSafetyCodec.Invalid();
        using var transaction = _db.BeginTransaction();
        if (!legacy)
        {
            using var jobs = Command("""
                CREATE TABLE jobs (
                  request_id TEXT PRIMARY KEY, kind TEXT NOT NULL, owner TEXT NOT NULL, grant_id TEXT NOT NULL,
                  deadline_ms INTEGER NOT NULL, allow_disconnected INTEGER NOT NULL CHECK(allow_disconnected IN (0,1)),
                  payload_hash TEXT NOT NULL, request_hash TEXT NOT NULL, state INTEGER NOT NULL,
                  submitted_ms INTEGER NOT NULL, started_ms INTEGER, completed_ms INTEGER, result_code TEXT,
                  payload BLOB, output BLOB, output_bytes INTEGER NOT NULL DEFAULT 0,
                  data_expired INTEGER NOT NULL DEFAULT 0 CHECK(data_expired IN (0,1))
                );
                CREATE INDEX jobs_queue ON jobs(state, submitted_ms);
                """);
            jobs.Transaction = transaction; jobs.ExecuteNonQuery();
        }
        using var schema = Command("""
            CREATE TABLE job_safety_metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1),store_id TEXT NOT NULL,seal BLOB NOT NULL);
            CREATE TABLE job_runtime_safety(singleton INTEGER PRIMARY KEY CHECK(singleton=1),sealed_record BLOB NOT NULL);
            PRAGMA user_version=2;
            """);
        schema.Transaction = transaction; schema.ExecuteNonQuery();
        using var header = Command("INSERT INTO job_safety_metadata VALUES(1,$id,$seal);", ("$id", id.ToString("D")), ("$seal", cipher));
        header.Transaction = transaction; header.ExecuteNonQuery();
        var safety = legacy
            ? new RuntimeSafetyRecord(id, RuntimeSafetyState.Quarantined, Guid.NewGuid(), null, "LEGACY_STORE_REVIEW_REQUIRED", NowMilliseconds())
            : RuntimeSafetyRecord.Clean(id, NowMilliseconds());
        using var guard = Command("INSERT INTO job_runtime_safety VALUES(1,$seal);", ("$seal", RuntimeSafetyCodec.Seal(safety, _protector)));
        guard.Transaction = transaction; guard.ExecuteNonQuery(); transaction.Commit();
        return id;
    }

    private Guid AuthenticateSafetyHeader()
    {
        var version = Convert.ToInt32(Scalar("PRAGMA user_version;"));
        if (version != 2) throw new JobRuntimeException(version == 1 ? "JOB_STORE_UPGRADE_REQUIRED" : "JOB_STORE_VERSION_UNSUPPORTED");
        using var command = Command("SELECT store_id,length(seal),seal FROM job_safety_metadata WHERE singleton=1;");
        using var reader = command.ExecuteReader();
        if (!reader.Read() || reader.GetInt64(1) is < 1 or > RuntimeSafetyCodec.MaximumCiphertext
            || !Guid.TryParseExact(reader.GetString(0), "D", out var id) || id == Guid.Empty
            || reader.GetString(0) != id.ToString("D")) throw RuntimeSafetyCodec.Invalid();
        byte[]? clear = null;
        try
        {
            clear = _protector.Unprotect((byte[])reader.GetValue(2), SafetyHeaderPurpose);
            if (clear is null || !CryptographicOperations.FixedTimeEquals(clear, SafetyHeader(id))) throw RuntimeSafetyCodec.Invalid();
        }
        catch (CryptographicException) { throw RuntimeSafetyCodec.Invalid(); }
        finally { if (clear is not null) CryptographicOperations.ZeroMemory(clear); }
        return id;
    }

    private void ValidateLegacyReceipts()
    {
        if (Convert.ToInt64(Scalar("SELECT COUNT(*) FROM jobs;")) > Limits.MaximumReceiptCount)
            throw new JobRuntimeException("JOB_RECEIPT_CAPACITY");
        using var command = Command("SELECT request_id FROM jobs;");
        var ids = new List<Guid>();
        using (var reader = command.ExecuteReader())
            while (reader.Read())
            {
                if (!Guid.TryParseExact(reader.GetString(0), "D", out var id) || id == Guid.Empty) throw new JobRuntimeException("JOB_STORE_CORRUPT");
                ids.Add(id);
            }
        foreach (var id in ids) _ = Find(id) ?? throw new JobRuntimeException("JOB_STORE_CORRUPT");
    }

    private static byte[] SafetyHeader(Guid id) => Encoding.UTF8.GetBytes($"JTS-JOB-SAFETY-V1\n{id:D}");
    private long NowMilliseconds() => _clock.GetUtcNow().ToUnixTimeMilliseconds();
    private RuntimeSafetyRecord ReadSafety()
    {
        using var command = Command("SELECT length(sealed_record),sealed_record FROM job_runtime_safety WHERE singleton=1;");
        using var reader = command.ExecuteReader();
        if (!reader.Read() || reader.GetInt64(0) is < 1 or > RuntimeSafetyCodec.MaximumCiphertext) throw RuntimeSafetyCodec.Invalid();
        return RuntimeSafetyCodec.Open((byte[])reader.GetValue(1), _storeId, _protector);
    }
    private void WriteSafety(RuntimeSafetyRecord record, SqliteTransaction transaction)
    {
        using var command = Command("UPDATE job_runtime_safety SET sealed_record=$seal WHERE singleton=1;",
            ("$seal", RuntimeSafetyCodec.Seal(record, _protector)));
        command.Transaction = transaction;
        if (command.ExecuteNonQuery() != 1) throw RuntimeSafetyCodec.Invalid();
    }
    private void RequireSafetyClean()
    {
        if (ReadSafety().State != RuntimeSafetyState.Clean) throw new JobRuntimeException("JOB_EXECUTOR_STATE_UNKNOWN");
    }
}
