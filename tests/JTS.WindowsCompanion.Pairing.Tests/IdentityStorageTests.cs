using System.Security.Cryptography;
using JTS.WindowsCompanion.Runtime;
using Xunit;

namespace JTS.WindowsCompanion.Pairing.Tests;

public sealed class IdentityStorageTests
{
    [Fact]
    public void CreateReopenKeepsExactPublicIdentityAndNeverWritesClearRecord()
    {
        using var fixture = new IdentityFixture();
        RelayIdentityDescription description;
        using (var identity = fixture.Create())
        {
            description = identity.Description;
            var bytes = File.ReadAllBytes(fixture.Path);
            Assert.False(bytes.AsSpan().IndexOf(Convert.FromBase64String(description.CertificateDerBase64)) >= 0);
            Assert.Equal(64, description.DeviceId.Length);
            Assert.Equal(description.DeviceId, identity.Identity.DeviceId);
            Assert.DoesNotContain(description.PublicKeySpkiBase64, identity.ToString());
        }
        using var reopened = fixture.Open(description.DeviceId);
        Assert.Equal(description, reopened.Description);
        var derivedId = Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(description.PublicKeySpkiBase64))).ToLowerInvariant();
        Assert.Equal(description.DeviceId, derivedId);
    }
    [Fact]
    public void LeaseAndExistingFilePreventDuplicateIdentityOrOverwrite()
    {
        using var fixture = new IdentityFixture();
        string device;
        using (var identity = fixture.Create())
        {
            device = identity.Description.DeviceId;
            Assert.ThrowsAny<IOException>(() => fixture.Open(device));
            Assert.ThrowsAny<IOException>(() => fixture.Create());
        }
        var before = File.ReadAllBytes(fixture.Path);
        Assert.Equal("IDENTITY_ALREADY_EXISTS", Assert.Throws<RelayIdentityStoreException>(() => fixture.Create()).Code);
        Assert.Equal(before, File.ReadAllBytes(fixture.Path));
        using var reopened = fixture.Open(device);
        reopened.Dispose(); reopened.Dispose();
        Assert.Throws<ObjectDisposedException>(() => reopened.Identity);
    }
    [Fact]
    public void MissingStateIsNotProvisionedByOpen()
    {
        using var fixture = new IdentityFixture();
        Assert.Equal("IDENTITY_NOT_INITIALIZED", Assert.Throws<RelayIdentityStoreException>(() => fixture.Open(new string('a', 64))).Code);
        Assert.False(File.Exists(fixture.Path));
        Assert.False(File.Exists(fixture.Path + ".lease"));
    }
    [Theory]
    [InlineData("device")]
    [InlineData("enrollment")]
    [InlineData("protector")]
    [InlineData("expiry")]
    [InlineData("clock")]
    public void WrongContextOrInvalidLifetimeNeverRotatesIdentity(string kind)
    {
        using var fixture = new IdentityFixture();
        string device; using (var identity = fixture.Create()) device = identity.Description.DeviceId;
        var before = File.ReadAllBytes(fixture.Path);
        using var wrongProtector = new TestProtector();
        if (kind == "expiry") fixture.Clock.Advance(TimeSpan.FromDays(366));
        if (kind == "clock") fixture.Clock.Advance(TimeSpan.FromMinutes(-6));
        Assert.Throws<RelayIdentityStoreException>(() => ProtectedRelayIdentityStore.Open(fixture.Path,
            kind == "enrollment" ? Guid.NewGuid() : fixture.EnrollmentId,
            kind == "device" ? new string('f', 64) : device,
            kind == "protector" ? wrongProtector : fixture.Protector, fixture.Clock));
        Assert.Equal(before, File.ReadAllBytes(fixture.Path));
    }
    [Theory]
    [InlineData("empty")]
    [InlineData("large")]
    [InlineData("tamper")]
    [InlineData("truncated")]
    public void CorruptCiphertextFailsWithoutReset(string kind)
    {
        using var fixture = new IdentityFixture();
        string device; using (var identity = fixture.Create()) device = identity.Description.DeviceId;
        var bytes = File.ReadAllBytes(fixture.Path);
        bytes = kind switch { "empty" => [], "large" => new byte[32769], "truncated" => bytes[..^1], _ => bytes };
        if (kind == "tamper") bytes[^1] ^= 1;
        File.WriteAllBytes(fixture.Path, bytes);
        Assert.Throws<RelayIdentityStoreException>(() => fixture.Open(device));
        Assert.Equal(bytes, File.ReadAllBytes(fixture.Path));
    }
    [Fact]
    public void DecryptedPrivateBufferIsErasedOnSuccessAndRejectedIdentity()
    {
        using var fixture = new IdentityFixture(); using var protector = new RetainingProtector();
        string device;
        using (var identity = ProtectedRelayIdentityStore.CreateNew(fixture.Path, fixture.EnrollmentId, protector, fixture.Clock))
            device = identity.Description.DeviceId;
        using (ProtectedRelayIdentityStore.Open(fixture.Path, fixture.EnrollmentId, device, protector, fixture.Clock))
            Assert.All(protector.LastClear!, b => Assert.Equal(0, b));
        Assert.Throws<RelayIdentityStoreException>(() => ProtectedRelayIdentityStore.Open(fixture.Path, fixture.EnrollmentId,
            new string('e', 64), protector, fixture.Clock));
        Assert.All(protector.LastClear!, b => Assert.Equal(0, b));
    }
    [Fact]
    public void ProtectionFailureDoesNotPublishAnIdentity()
    {
        using var fixture = new IdentityFixture();
        Assert.Throws<CryptographicException>(() => ProtectedRelayIdentityStore.CreateNew(fixture.Path, fixture.EnrollmentId, new BrokenProtector(), fixture.Clock));
        Assert.False(File.Exists(fixture.Path));
        using var subsequentExplicitProvision = fixture.Create();
        Assert.NotNull(subsequentExplicitProvision.Identity);
    }
    [Fact]
    public void AccessChecksRunBeforeDecryptionAndAfterLeaseAndCreation()
    {
        using var fixture = new IdentityFixture(); var checks = 0;
        using var identity = ProtectedRelayIdentityStore.CreateNew(fixture.Path, fixture.EnrollmentId, fixture.Protector, fixture.Clock, () => checks++);
        Assert.Equal(3, checks); var device = identity.Description.DeviceId; identity.Dispose();
        Assert.Throws<UnauthorizedAccessException>(() => ProtectedRelayIdentityStore.Open(fixture.Path, fixture.EnrollmentId, device,
            fixture.Protector, fixture.Clock, () => throw new UnauthorizedAccessException()));
        checks = 0;
        using var opened = ProtectedRelayIdentityStore.Open(fixture.Path, fixture.EnrollmentId, device, fixture.Protector, fixture.Clock, () => checks++);
        Assert.Equal(2, checks);
    }
    [Fact]
    public void ProvisioningRequiresPrivateAbsolutePathAndNonemptyEnrollment()
    {
        using var fixture = new IdentityFixture();
        Assert.Throws<ArgumentException>(() => ProtectedRelayIdentityStore.CreateNew("relative.identity", fixture.EnrollmentId, fixture.Protector, fixture.Clock));
        Assert.Throws<ArgumentException>(() => ProtectedRelayIdentityStore.CreateNew(fixture.Path, Guid.Empty, fixture.Protector, fixture.Clock));
        // Creating a Windows symlink itself may need a privilege the dedicated account must not have.
        if (!OperatingSystem.IsWindows())
        {
            var target = System.IO.Path.Combine(fixture.Directory.FullName, "target"); File.WriteAllBytes(target, [1]);
            File.CreateSymbolicLink(fixture.Path, target);
            Assert.Throws<ArgumentException>(() => fixture.Create());
            Assert.Equal(new byte[] { 1 }, File.ReadAllBytes(target));
        }
    }
    private sealed class RetainingProtector : ITaskPayloadProtector, IDisposable
    {
        private readonly TestProtector _inner = new();
        internal byte[]? LastClear { get; private set; }
        public byte[] Protect(ReadOnlySpan<byte> clear, ReadOnlySpan<byte> purpose) => _inner.Protect(clear, purpose);
        public byte[] Unprotect(ReadOnlySpan<byte> cipher, ReadOnlySpan<byte> purpose) => LastClear = _inner.Unprotect(cipher, purpose);
        public void Dispose() => _inner.Dispose();
    }
    private sealed class BrokenProtector : ITaskPayloadProtector
    {
        public byte[] Protect(ReadOnlySpan<byte> clear, ReadOnlySpan<byte> purpose) => throw new CryptographicException();
        public byte[] Unprotect(ReadOnlySpan<byte> cipher, ReadOnlySpan<byte> purpose) => throw new CryptographicException();
    }
}

internal sealed class IdentityFixture : IDisposable
{
    internal DirectoryInfo Directory { get; } = System.IO.Directory.CreateTempSubdirectory("jts-relay-identity-");
    internal string Path => System.IO.Path.Combine(Directory.FullName, "identity.sealed");
    internal Guid EnrollmentId { get; } = Guid.NewGuid();
    internal TestProtector Protector { get; } = new();
    internal TestClock Clock { get; } = new();
    internal IdentityFixture()
    {
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(Directory.FullName, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }
    internal StoredRelayIdentity Create() => ProtectedRelayIdentityStore.CreateNew(Path, EnrollmentId, Protector, Clock);
    internal StoredRelayIdentity Open(string device) => ProtectedRelayIdentityStore.Open(Path, EnrollmentId, device, Protector, Clock);
    public void Dispose() { Protector.Dispose(); Directory.Delete(true); }
}
