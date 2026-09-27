using Microsoft.Data.Sqlite;
using System.Security.Cryptography;
using System.Text;

namespace JTS.WindowsCompanion.Runtime.Tests;

internal sealed class RuntimeFixture : IDisposable
{
    private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("jts-job-runtime-");
    internal string DatabasePath => Path.Combine(_directory.FullName, "jobs.sqlite");
    internal string DirectoryPath => _directory.FullName;
    internal string Owner { get; } = new('a', 64);
    internal Guid Grant { get; } = Guid.NewGuid();
    internal ITaskPayloadProtector Protector { get; } = new FixtureProtector();
    internal DurableJobStore Open(DurableJobLimits? limits = null, TimeProvider? clock = null)
        => File.Exists(DatabasePath) ? new(DatabasePath, Protector, limits, clock)
            : DurableJobStore.CreateNew(DatabasePath, Protector, limits, clock);
    internal JobSubmission Job(bool allowDisconnected = false, string payload = "secret-script-fixture", Guid? id = null,
        DateTimeOffset? deadline = null) => new(id ?? Guid.NewGuid(), "fixture.exec", Owner, Grant,
            deadline ?? DateTimeOffset.UtcNow.AddMinutes(1), Encoding.UTF8.GetBytes(payload), allowDisconnected);
    internal SqliteConnection Inspect()
    {
        var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = DatabasePath, Pooling = false }.ToString());
        db.Open(); return db;
    }
    public void Dispose() => _directory.Delete(recursive: true);
}

internal sealed class FixtureAuthority : IJobGrantAuthority
{
    internal bool Allowed { get; set; } = true;
    internal int Calls { get; private set; }
    public ValueTask<bool> CanExecuteAsync(JobBinding binding, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); Calls++; return ValueTask.FromResult(Allowed);
    }
}

internal sealed class FixtureExecutor : IJobExecutor
{
    internal int Calls { get; private set; }
    internal Func<JobBinding, ReadOnlyMemory<byte>, IJobOutputSink, CancellationToken, ValueTask<JobExecutionResult>>? Execute { get; init; }
    public ValueTask<JobExecutionResult> ExecuteAsync(JobBinding binding, ReadOnlyMemory<byte> payload, IJobOutputSink output, CancellationToken cancellationToken)
    {
        Calls++;
        return Execute is null ? ValueTask.FromResult(new JobExecutionResult(true, "OK")) : Execute(binding, payload, output, cancellationToken);
    }
}

// Test-only deterministic AEAD. Production has no default or fallback protector.
internal sealed class FixtureProtector : ITaskPayloadProtector
{
    private static readonly byte[] Key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    public byte[] Protect(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> purpose)
    {
        using var aes = new AesGcm(Key, 16);
        var material = new byte[plaintext.Length + purpose.Length]; plaintext.CopyTo(material); purpose.CopyTo(material.AsSpan(plaintext.Length));
        var nonce = SHA256.HashData(material).AsSpan(0, 12).ToArray();
        var result = new byte[28 + plaintext.Length]; nonce.CopyTo(result, 0);
        aes.Encrypt(nonce, plaintext, result.AsSpan(28), result.AsSpan(12, 16), purpose);
        CryptographicOperations.ZeroMemory(material);
        return result;
    }
    public byte[] Unprotect(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> purpose)
    {
        if (ciphertext.Length < 28) throw new CryptographicException();
        using var aes = new AesGcm(Key, 16);
        var result = new byte[ciphertext.Length - 28];
        aes.Decrypt(ciphertext[..12], ciphertext[28..], ciphertext.Slice(12, 16), result, purpose);
        return result;
    }
}

internal sealed class FixtureClock(DateTimeOffset now) : TimeProvider
{
    private DateTimeOffset _now = now;
    public override DateTimeOffset GetUtcNow() => _now;
    internal void Advance(TimeSpan amount) => _now += amount;
}
