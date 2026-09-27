using System.Security.Cryptography;
using JTS.WindowsCompanion.Control;
using JTS.WindowsCompanion.Runtime;

// Test-only disposable policy/protector/executor. Never loads real grants or executes a shell.
internal sealed class ControlInteropFixture : IAsyncDisposable, IJobExecutor, ITaskPayloadProtector
{
    private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("jts-control-interop-");
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    private readonly DurableControlGrantStore _grants;
    private readonly DurableJobStore _store;
    internal Guid GrantId { get; } = Guid.NewGuid();
    internal CompanionControlHost Host { get; }

    internal ControlInteropFixture(string owner)
    {
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(_directory.FullName,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var grant = new ControlGrant(owner, GrantId, DateTimeOffset.UtcNow.AddMinutes(2), Enum.GetValues<ControlOperation>(),
            ["fixture.echo", "fixture.block"], allowDisconnected: true);
        _grants = DurableControlGrantStore.CreateNew(Path.Combine(_directory.FullName, "grants.sqlite"), this);
        _grants.ApproveLocally(grant); // Test fixture only: no actual Windows consent is implied.
        _store = DurableJobStore.CreateNew(Path.Combine(_directory.FullName, "jobs.sqlite"), this);
        Host = new(_store, _grants, this);
    }

    public async ValueTask<JobExecutionResult> ExecuteAsync(JobBinding binding, ReadOnlyMemory<byte> payload,
        IJobOutputSink output, CancellationToken token)
    {
        if (binding.Kind == "fixture.block") await Task.Delay(Timeout.Infinite, token);
        else if (binding.Kind != "fixture.echo") throw new InvalidOperationException("fixture_kind_invalid");
        await output.AppendAsync(payload, token);
        return new(true, "OK");
    }

    public byte[] Protect(ReadOnlySpan<byte> plain, ReadOnlySpan<byte> purpose)
    {
        var result = new byte[28 + plain.Length]; RandomNumberGenerator.Fill(result.AsSpan(0, 12));
        using var aes = new AesGcm(_key, 16);
        aes.Encrypt(result.AsSpan(0, 12), plain, result.AsSpan(28), result.AsSpan(12, 16), purpose);
        return result;
    }
    public byte[] Unprotect(ReadOnlySpan<byte> value, ReadOnlySpan<byte> purpose)
    {
        var result = new byte[value.Length - 28]; using var aes = new AesGcm(_key, 16);
        aes.Decrypt(value[..12], value[28..], value.Slice(12, 16), result, purpose); return result;
    }

    public async ValueTask DisposeAsync()
    {
        await Host.DisposeAsync(); _store.Dispose(); _grants.Dispose();
        CryptographicOperations.ZeroMemory(_key); _directory.Delete(recursive: true);
    }
}
