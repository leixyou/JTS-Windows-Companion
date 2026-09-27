using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Pairing;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.AuthorityProvisioner.Tests;

internal sealed class ProvisioningFixture : IDisposable, IProvisioningIdentityFactory
{
    internal const string Authority = "S-1-5-21-1-2-3-1100", Worker = "S-1-5-21-1-2-3-1101";
    internal string Root { get; } = Path.Combine(PhysicalTemporaryRoot(), "jts-provision-test-" + Guid.NewGuid().ToString("N"));
    internal Guid Enrollment { get; } = Guid.NewGuid();
    internal TestClock Clock { get; } = new();
    internal FixtureProtector Protector { get; } = new();
    internal ProvisioningPaths Paths { get; }
    internal ProvisioningIntent Intent { get; }
    internal Action? BeforeCreate { get; set; }
    internal Action? BeforeOpen { get; set; }
    internal ProvisioningFixture()
    {
        Paths = new(Root, Enrollment); Directory.CreateDirectory(Paths.State);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(Root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        Intent = new(Enrollment, Authority, Worker, Clock.Now - TimeSpan.FromMinutes(1), Clock.Now + TimeSpan.FromMinutes(20));
    }
    internal ProvisioningState State(Action<string>? access = null) => new(Protector, this, access ?? (_ => { }), Clock);
    public StoredRelayIdentity Create(string path, ProvisioningIntent intent)
    { BeforeCreate?.Invoke(); return ProtectedRelayIdentityStore.CreateNew(path, intent.EnrollmentId, Protector, Clock); }
    public StoredRelayIdentity Open(string path, ProvisioningIntent intent, string deviceId)
    { BeforeOpen?.Invoke(); return ProtectedRelayIdentityStore.Open(path, intent.EnrollmentId, deviceId, Protector, Clock); }
    internal byte[] IntentBytes() => JsonSerializer.SerializeToUtf8Bytes(new
    {
        schemaVersion = 1, operation = "initialize-new-authority", enrollmentId = Enrollment, authoritySid = Authority, workerSid = Worker,
        createdAt = Intent.CreatedAt.ToString("O"), expiresAt = Intent.ExpiresAt.ToString("O"),
    });
    public void Dispose() { Protector.Dispose(); Directory.Delete(Root, recursive: true); }
    private static string PhysicalTemporaryRoot()
    {
        var path = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar);
        for (DirectoryInfo? directory = new(path); directory is not null; directory = directory.Parent)
            if (directory.LinkTarget is not null)
                return Path.Combine(directory.ResolveLinkTarget(returnFinalTarget: true)!.FullName, Path.GetRelativePath(directory.FullName, path));
        return path;
    }
}

internal sealed class TestClock : TimeProvider
{
    internal DateTimeOffset Now { get; set; } = new(2026, 9, 19, 0, 0, 0, TimeSpan.Zero);
    public override DateTimeOffset GetUtcNow() => Now;
}

internal sealed class FixtureProtector : ITaskPayloadProtector, IDisposable
{
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    public byte[] Protect(ReadOnlySpan<byte> plain, ReadOnlySpan<byte> purpose)
    {
        var result = new byte[28 + plain.Length]; RandomNumberGenerator.Fill(result.AsSpan(0, 12));
        using var aes = new AesGcm(_key, 16); aes.Encrypt(result.AsSpan(0, 12), plain, result.AsSpan(28), result.AsSpan(12, 16), purpose); return result;
    }
    public byte[] Unprotect(ReadOnlySpan<byte> cipher, ReadOnlySpan<byte> purpose)
    {
        if (cipher.Length < 28) throw new CryptographicException();
        var result = new byte[cipher.Length - 28]; using var aes = new AesGcm(_key, 16);
        aes.Decrypt(cipher[..12], cipher[28..], cipher.Slice(12, 16), result, purpose); return result;
    }
    public void Dispose() => CryptographicOperations.ZeroMemory(_key);
}
