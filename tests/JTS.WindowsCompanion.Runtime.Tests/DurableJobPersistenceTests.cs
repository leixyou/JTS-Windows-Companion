using Microsoft.Data.Sqlite;
using System.Text;
using Xunit;

namespace JTS.WindowsCompanion.Runtime.Tests;

public sealed class DurableJobPersistenceTests
{
    [Fact]
    public async Task SqliteWalPersistsEncryptedPayloadOutputAndTerminalReceiptAcrossReopen()
    {
        using var fixture = new RuntimeFixture();
        var job = fixture.Job(payload: "UNIQUE-PRIVATE-POWERSHELL-CONTENT");
        var executor = new FixtureExecutor { Execute = async (_, _, output, token) =>
        {
            await output.AppendAsync(Encoding.UTF8.GetBytes("UNIQUE-PRIVATE-OUTPUT-CONTENT"), token);
            return new JobExecutionResult(true, "OK");
        } };
        using (var store = fixture.Open())
        {
            await using (var runtime = new DurableJobRuntime(store, new FixtureAuthority(), executor))
            {
                runtime.SetOwnerConnected(fixture.Owner, true);
                await runtime.SubmitAsync(job);
                using (var db = fixture.Inspect())
                {
                    using var command = db.CreateCommand(); command.CommandText = "PRAGMA journal_mode;";
                    Assert.Equal("wal", command.ExecuteScalar());
                }
                Assert.True(await runtime.RunNextAsync());
                Assert.Equal("UNIQUE-PRIVATE-OUTPUT-CONTENT", Encoding.UTF8.GetString(store.ReadOutput(job.Binding.RequestId, fixture.Owner, fixture.Grant)));
                foreach (var path in Directory.GetFiles(fixture.DirectoryPath))
                {
                    if (path.EndsWith(".lease", StringComparison.Ordinal)) continue;
                    var bytes = await File.ReadAllBytesAsync(path);
                    Assert.False(bytes.AsSpan().IndexOf(Encoding.UTF8.GetBytes("UNIQUE-PRIVATE-POWERSHELL-CONTENT")) >= 0);
                    Assert.False(bytes.AsSpan().IndexOf(Encoding.UTF8.GetBytes("UNIQUE-PRIVATE-OUTPUT-CONTENT")) >= 0);
                }
            }
        }
        using var reopened = fixture.Open();
        await using var nextRuntime = new DurableJobRuntime(reopened, new FixtureAuthority(), executor);
        Assert.Equal(DurableJobState.Succeeded, reopened.Get(job.Binding.RequestId, fixture.Owner, fixture.Grant).State);
        Assert.False(await nextRuntime.RunNextAsync());
        Assert.Equal(1, executor.Calls);
    }

    [Fact]
    public async Task ConcurrentRepeatedSubmissionReturnsOneImmutableReceipt()
    {
        using var fixture = new RuntimeFixture(); using var store = fixture.Open();
        var executor = new FixtureExecutor();
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), executor);
        runtime.SetOwnerConnected(fixture.Owner, true);
        var job = fixture.Job();
        var receipts = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => runtime.SubmitAsync(job)));
        Assert.All(receipts, receipt => Assert.Equal(job.Binding, receipt.Binding));
        await runtime.RunNextAsync();
        await runtime.SubmitAsync(job);
        Assert.False(await runtime.RunNextAsync());
        Assert.Equal(1, executor.Calls);
    }

    [Theory]
    [InlineData("payload")]
    [InlineData("owner")]
    [InlineData("grant")]
    [InlineData("deadline")]
    [InlineData("disconnect")]
    [InlineData("kind")]
    public async Task SameRequestIdCannotChangeExecutionBinding(string changed)
    {
        using var fixture = new RuntimeFixture(); using var store = fixture.Open();
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), new FixtureExecutor());
        runtime.SetOwnerConnected(fixture.Owner, true);
        runtime.SetOwnerConnected(new string('b', 64), true);
        var job = fixture.Job(); await runtime.SubmitAsync(job);
        var binding = job.Binding;
        var other = new JobSubmission(binding.RequestId, changed == "kind" ? "another.exec" : binding.Kind,
            changed == "owner" ? new string('b', 64) : binding.OwnerDeviceId,
            changed == "grant" ? Guid.NewGuid() : binding.GrantId,
            changed == "deadline" ? binding.Deadline.AddSeconds(1) : binding.Deadline,
            changed == "payload" ? Encoding.UTF8.GetBytes("changed") : job.Payload,
            changed == "disconnect");
        var error = await Assert.ThrowsAsync<JobRuntimeException>(() => runtime.SubmitAsync(other));
        Assert.Equal("JOB_IDEMPOTENCY_CONFLICT", error.Code);
    }

    [Fact]
    public void RestartWithRunningJobQuarantinesRuntimeAndCancelsAllQueuedWork()
    {
        using var fixture = new RuntimeFixture();
        var running = fixture.Job(allowDisconnected: true);
        var queued = fixture.Job(allowDisconnected: true);
        var interactive = fixture.Job();
        using (var before = fixture.Open())
        {
            before.Submit(running); before.Start(running.Binding.RequestId);
            before.Submit(queued); before.Submit(interactive);
        }
        using var store = fixture.Open();
        var authority = new FixtureAuthority { Allowed = false };
        var executor = new FixtureExecutor();
        Assert.Equal("JOB_EXECUTOR_STATE_UNKNOWN", Assert.Throws<JobRuntimeException>(() =>
            new DurableJobRuntime(store, authority, executor)).Code);
        Assert.Equal(DurableJobState.Interrupted, store.Get(running.Binding.RequestId, fixture.Owner, fixture.Grant).State);
        Assert.Equal(DurableJobState.Cancelled, store.Get(interactive.Binding.RequestId, fixture.Owner, fixture.Grant).State);
        Assert.Equal(DurableJobState.Cancelled, store.Get(queued.Binding.RequestId, fixture.Owner, fixture.Grant).State);
        Assert.Equal(0, authority.Calls); Assert.Equal(0, executor.Calls);
        Assert.Equal(running.Binding.RequestId, store.GetRecoveryRequirement()!.RequestId);
    }

    [Fact]
    public async Task CleanRestartStillRevalidatesQueuedDetachedJobs()
    {
        using var fixture = new RuntimeFixture(); var queued = fixture.Job(allowDisconnected: true);
        var interactive = fixture.Job();
        using (var before = fixture.Open()) { before.Submit(queued); before.Submit(interactive); }
        using var store = fixture.Open(); var authority = new FixtureAuthority { Allowed = false };
        var executor = new FixtureExecutor();
        await using var runtime = new DurableJobRuntime(store, authority, executor);
        Assert.Null(store.GetRecoveryRequirement());
        Assert.Equal(DurableJobState.Cancelled, store.Get(interactive.Binding.RequestId, fixture.Owner, fixture.Grant).State);
        Assert.True(await runtime.RunNextAsync()); Assert.False(await runtime.RunNextAsync());
        Assert.Equal(DurableJobState.Cancelled, store.Get(queued.Binding.RequestId, fixture.Owner, fixture.Grant).State);
        Assert.Equal(1, authority.Calls); Assert.Equal(0, executor.Calls);
    }

    [Fact]
    public async Task EncryptedPayloadCannotBeSwappedBetweenJobs()
    {
        using var fixture = new RuntimeFixture(); using var store = fixture.Open();
        var executor = new FixtureExecutor();
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), executor);
        var first = fixture.Job(allowDisconnected: true); var other = fixture.Job(allowDisconnected: true, payload: "second secret");
        await runtime.SubmitAsync(first); await runtime.SubmitAsync(other);
        using (var db = fixture.Inspect())
        {
            using var command = db.CreateCommand();
            command.CommandText = "UPDATE jobs SET payload=(SELECT payload FROM jobs WHERE request_id=$source) WHERE request_id=$target;";
            command.Parameters.AddWithValue("$source", other.Binding.RequestId.ToString("D"));
            command.Parameters.AddWithValue("$target", first.Binding.RequestId.ToString("D"));
            command.ExecuteNonQuery();
        }
        var error = Assert.Throws<JobRuntimeException>(() => store.ReadPayload(first.Binding));
        Assert.Equal("JOB_PAYLOAD_AUTHENTICATION_FAILED", error.Code);
        Assert.Equal(0, executor.Calls);
    }

    [Fact]
    public void SecondStoreOrRuntimeCannotRecoverAnActiveOwnersLedger()
    {
        using var fixture = new RuntimeFixture(); using var store = fixture.Open();
        Assert.Throws<IOException>(() => fixture.Open());
    }

    [Fact]
    public async Task WrongOwnerAndGrantCannotReadOrCancelJob()
    {
        using var fixture = new RuntimeFixture(); using var store = fixture.Open();
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), new FixtureExecutor());
        var job = fixture.Job(allowDisconnected: true); await runtime.SubmitAsync(job);
        Assert.Throws<JobRuntimeException>(() => store.Get(job.Binding.RequestId, new string('b', 64), fixture.Grant));
        Assert.Throws<JobRuntimeException>(() => store.ReadOutput(job.Binding.RequestId, fixture.Owner, Guid.NewGuid()));
        Assert.Throws<JobRuntimeException>(() => runtime.Cancel(job.Binding.RequestId, new string('b', 64), fixture.Grant));
        Assert.Equal(DurableJobState.Queued, store.Get(job.Binding.RequestId, fixture.Owner, fixture.Grant).State);
    }

    [Fact]
    public async Task RetentionErasesDataButKeepsIdempotencyReceipt()
    {
        using var fixture = new RuntimeFixture();
        var clock = new FixtureClock(DateTimeOffset.UtcNow);
        using var store = fixture.Open(clock: clock);
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), new FixtureExecutor(), clock);
        var job = fixture.Job(allowDisconnected: true); await runtime.SubmitAsync(job); await runtime.RunNextAsync();
        clock.Advance(TimeSpan.FromDays(8)); store.PruneExpiredData();
        var receipt = store.Get(job.Binding.RequestId, fixture.Owner, fixture.Grant);
        Assert.True(receipt.DataExpired); Assert.Equal(DurableJobState.Succeeded, receipt.State);
        Assert.Throws<JobRuntimeException>(() => store.ReadOutput(job.Binding.RequestId, fixture.Owner, fixture.Grant));
        Assert.Equal(receipt, await runtime.SubmitAsync(job));
        Assert.False(await runtime.RunNextAsync());
    }
}
