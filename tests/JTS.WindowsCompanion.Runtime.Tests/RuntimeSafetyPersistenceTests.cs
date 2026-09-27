using Xunit;

namespace JTS.WindowsCompanion.Runtime.Tests;

public sealed class RuntimeSafetyPersistenceTests
{
    [Fact]
    public void OpeningMissingStoreCannotSilentlyProvisionAndProvisioningCannotOverwrite()
    {
        using var f = new RuntimeFixture();
        Assert.Equal("JOB_STORE_NOT_INITIALIZED", Assert.Throws<JobRuntimeException>(() =>
            new DurableJobStore(f.DatabasePath, f.Protector)).Code);
        Assert.False(File.Exists(f.DatabasePath));
        using (f.Open()) { }
        Assert.Throws<IOException>(() => DurableJobStore.CreateNew(f.DatabasePath, f.Protector));
        using var reopened = f.Open(); Assert.Null(reopened.GetRecoveryRequirement());
    }

    [Theory]
    [InlineData("DELETE FROM job_runtime_safety;")]
    [InlineData("UPDATE job_runtime_safety SET sealed_record=zeroblob(59);")]
    [InlineData("UPDATE job_runtime_safety SET sealed_record=zeroblob(8193);")]
    [InlineData("DELETE FROM job_safety_metadata;")]
    [InlineData("UPDATE job_safety_metadata SET seal=zeroblob(59);")]
    public void MissingCorruptOrOversizedSafetyRecordNeverResetsToClean(string sql)
    {
        using var f = new RuntimeFixture(); using (f.Open()) { }
        SafetyFixture.Sql(f, sql);
        Assert.Equal("JOB_SAFETY_AUTHENTICATION_FAILED", Assert.Throws<JobRuntimeException>(() => f.Open()).Code);
    }

    [Fact]
    public void GuardFromAnotherStoreCannotAuthenticateEvenWithSameProtector()
    {
        using var a = new RuntimeFixture(); using var b = new RuntimeFixture();
        byte[] guard;
        using (a.Open()) { guard = SafetyFixture.ReadGuard(a); }
        using (b.Open()) { }
        SafetyFixture.ReplaceGuard(b, guard);
        Assert.Equal("JOB_SAFETY_AUTHENTICATION_FAILED", Assert.Throws<JobRuntimeException>(() => b.Open()).Code);
    }

    [Fact]
    public void UnexpectedRunningRowWithoutDispatchMarkerStillQuarantines()
    {
        using var f = new RuntimeFixture(); var job = f.Job(allowDisconnected: true);
        using (var store = f.Open()) store.Submit(job);
        SafetyFixture.Sql(f, "UPDATE jobs SET state=1;");
        using var reopened = f.Open();
        Assert.Equal("RUNTIME_RESTART_INTERRUPTED", reopened.GetRecoveryRequirement()!.Reason);
        Assert.Equal(DurableJobState.Interrupted, reopened.Get(job.Binding.RequestId, f.Owner, f.Grant).State);
    }

    [Fact]
    public void LegacyUpgradeIsExplicitPreservesReceiptsAndAlwaysRequiresRecovery()
    {
        using var f = new RuntimeFixture(); var job = f.Job(allowDisconnected: true);
        using (var store = f.Open()) { store.Submit(job); store.Start(job.Binding.RequestId); store.Finish(job.Binding.RequestId, DurableJobState.Succeeded, "OK"); }
        // Schema 1 is the unchanged jobs table without the new metadata and guard tables.
        SafetyFixture.Sql(f, "DROP TABLE job_safety_metadata; DROP TABLE job_runtime_safety; PRAGMA user_version=1;");
        Assert.Equal("JOB_STORE_UPGRADE_REQUIRED", Assert.Throws<JobRuntimeException>(() => f.Open()).Code);
        using (var upgraded = DurableJobStore.UpgradeLegacy(f.DatabasePath, f.Protector))
        {
            Assert.Equal("LEGACY_STORE_REVIEW_REQUIRED", upgraded.GetRecoveryRequirement()!.Reason);
            Assert.Equal(DurableJobState.Succeeded, upgraded.Get(job.Binding.RequestId, f.Owner, f.Grant).State);
            Assert.Throws<JobRuntimeException>(() => new DurableJobRuntime(upgraded, new FixtureAuthority(), new FixtureExecutor()));
        }
        using var reopened = f.Open(); Assert.NotNull(reopened.GetRecoveryRequirement());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    public void UnknownSchemaIsNotSilentlyInitializedOrMigrated(int version)
    {
        using var f = new RuntimeFixture(); using (f.Open()) { }
        SafetyFixture.Sql(f, $"PRAGMA user_version={version};");
        Assert.Equal("JOB_STORE_VERSION_UNSUPPORTED", Assert.Throws<JobRuntimeException>(() => f.Open()).Code);
        Assert.Equal("JOB_STORE_VERSION_UNSUPPORTED", Assert.Throws<JobRuntimeException>(() => DurableJobStore.UpgradeLegacy(f.DatabasePath, f.Protector)).Code);
    }
}

internal static class SafetyFixture
{
    internal static void Sql(RuntimeFixture fixture, string sql)
    {
        using var db = fixture.Inspect(); using var command = db.CreateCommand();
        command.CommandText = sql; command.ExecuteNonQuery();
    }
    internal static byte[] ReadGuard(RuntimeFixture fixture)
    {
        using var db = fixture.Inspect(); using var command = db.CreateCommand();
        command.CommandText = "SELECT sealed_record FROM job_runtime_safety;"; return (byte[])command.ExecuteScalar()!;
    }
    internal static void ReplaceGuard(RuntimeFixture fixture, byte[] guard)
    {
        using var db = fixture.Inspect(); using var command = db.CreateCommand();
        command.CommandText = "UPDATE job_runtime_safety SET sealed_record=$guard;";
        command.Parameters.AddWithValue("$guard", guard); command.ExecuteNonQuery();
    }
    internal static JobSubmission Interrupt(DurableJobStore store, RuntimeFixture f)
    {
        var job = f.Job(allowDisconnected: true); store.Submit(job); store.Start(job.Binding.RequestId);
        store.QuarantineExecution(job.Binding.RequestId, "EXECUTOR_STATE_UNKNOWN"); return job;
    }
}
