using Microsoft.Data.Sqlite;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.Control.Tests;

internal sealed class ControlPolicyFixture : IDisposable
{
    internal DirectoryInfo Directory { get; } = System.IO.Directory.CreateTempSubdirectory("jts-policy-test-");
    internal FixtureProtector Protector { get; } = new();
    internal string Path => System.IO.Path.Combine(Directory.FullName, "policy.sqlite");
    internal string Owner { get; } = new('a', 64);
    internal PolicyTestClock Clock { get; } = new();
    internal ControlPolicyFixture()
    {
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(Directory.FullName,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }
    internal DurableControlGrantStore Create(int capacity = 4096) => DurableControlGrantStore.CreateNew(Path, Protector, capacity, Clock);
    internal DurableControlGrantStore Open() => new(Path, Protector, clock: Clock);
    internal ControlGrant Grant(Guid? id = null, string? owner = null, int hours = 1) => new(owner ?? Owner,
        id ?? Guid.NewGuid(), Clock.GetUtcNow().AddHours(hours), Enum.GetValues<ControlOperation>(), ["fixture.sensitive_permission"], true);
    internal object? Sql(string sql, params (string Name, object Value)[] args)
    {
        using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = Path, Pooling = false }.ToString());
        db.Open(); using var cmd = db.CreateCommand(); cmd.CommandText = sql;
        foreach (var arg in args) cmd.Parameters.AddWithValue(arg.Name, arg.Value);
        return cmd.ExecuteScalar();
    }
    public void Dispose() { Protector.Dispose(); Directory.Delete(true); }
}

internal sealed class PolicyTestClock : TimeProvider
{
    private DateTimeOffset _now = new(2026, 9, 19, 0, 0, 0, TimeSpan.Zero);
    public override DateTimeOffset GetUtcNow() => _now;
    internal void Advance(TimeSpan duration) => _now += duration;
}

internal sealed class PolicyTestExecutor : IJobExecutor
{
    internal int Executions;
    public ValueTask<JobExecutionResult> ExecuteAsync(JobBinding binding, ReadOnlyMemory<byte> payload, IJobOutputSink output, CancellationToken token)
    { Interlocked.Increment(ref Executions); return ValueTask.FromResult(new JobExecutionResult(true, "OK")); }
}

internal sealed class PolicyTestAuthority(IControlGrantProvider provider) : IJobGrantAuthority
{
    public async ValueTask<bool> CanExecuteAsync(JobBinding binding, CancellationToken token)
        => (await provider.FindAsync(binding.OwnerDeviceId, binding.GrantId, token))?.Allows(binding) == true;
}
