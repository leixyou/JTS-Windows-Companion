using System.Security.Cryptography;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Security;
using JTS.WindowsCompanion.Windows.Security;

namespace JTS.WindowsCompanion.Tests;

public sealed class WindowsIdentityTests
{
    [Fact]
    public async Task Identity_PersistsStableP256KeyThroughProtectorAbstraction()
    {
        using var temporary = new TemporaryDirectory();
        var identityPath = Path.Combine(temporary.Path, "identity.json");
        var protector = new TestProtector();
        CompanionIdentityMetadata firstMetadata;
        byte[] firstSignature;
        var payload = "pairing-payload"u8.ToArray();
        using (var identity = new DpapiCompanionIdentity(identityPath, protector))
        {
            firstMetadata = await identity.GetMetadataAsync(CancellationToken.None);
            firstSignature = await identity.SignAsync(payload, CancellationToken.None);
        }

        using var reloaded = new DpapiCompanionIdentity(identityPath, protector);
        var secondMetadata = await reloaded.GetMetadataAsync(CancellationToken.None);
        var secondSignature = await reloaded.SignAsync(payload, CancellationToken.None);

        Assert.Equal(firstMetadata, secondMetadata);
        using var verifier = ECDsa.Create();
        verifier.ImportSubjectPublicKeyInfo(Convert.FromBase64String(firstMetadata.PublicKeyBase64), out _);
        Assert.True(verifier.VerifyData(payload, firstSignature, HashAlgorithmName.SHA256));
        Assert.True(verifier.VerifyData(payload, secondSignature, HashAlgorithmName.SHA256));
        Assert.DoesNotContain(Convert.ToBase64String(payload), await File.ReadAllTextAsync(identityPath), StringComparison.Ordinal);
    }

    [Fact]
    public async Task PeerStore_ProtectsGrantAndNeverOverwritesDifferentIdentity()
    {
        using var temporary = new TemporaryDirectory();
        var storePath = Path.Combine(temporary.Path, "paired-peer.json");
        var protector = new TestProtector();
        var approved = new CompanionPeerGrant(CreatePeer(), DateTimeOffset.UtcNow);
        using (var store = new DpapiCompanionPeerStore(storePath, protector))
        {
            await store.SaveIfAbsentAsync(approved, CancellationToken.None);
        }

        var persistedText = await File.ReadAllTextAsync(storePath);
        Assert.DoesNotContain(approved.Identity.DeviceId.ToString("D"), persistedText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(approved.Identity.FingerprintSha256, persistedText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(approved.Identity.PublicKeyBase64, persistedText, StringComparison.Ordinal);

        using var reloaded = new DpapiCompanionPeerStore(storePath, protector);
        var loaded = await reloaded.LoadAsync(CancellationToken.None);
        Assert.Equal(approved, loaded);
        var mismatch = await Assert.ThrowsAsync<CompanionProtocolException>(async () =>
            await reloaded.SaveIfAbsentAsync(
                new CompanionPeerGrant(CreatePeer(), DateTimeOffset.UtcNow),
                CancellationToken.None));
        Assert.Equal("PAIRING_IDENTITY_MISMATCH", mismatch.Code);
        Assert.Equal(approved, await reloaded.LoadAsync(CancellationToken.None));

        await reloaded.ClearAsync(CancellationToken.None);
        Assert.Null(await reloaded.LoadAsync(CancellationToken.None));
    }

    [Fact]
    public async Task PeerStore_FailsClosedWhenProtectedEnvelopeIsMalformed()
    {
        using var temporary = new TemporaryDirectory();
        var storePath = Path.Combine(temporary.Path, "paired-peer.json");
        await File.WriteAllTextAsync(
            storePath,
            "{\"version\":1,\"protectedGrantBase64\":\"not-base64\"}");
        using var store = new DpapiCompanionPeerStore(storePath, new TestProtector());

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await store.LoadAsync(CancellationToken.None));
    }

    private static CompanionPeerIdentity CreatePeer()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = key.ExportSubjectPublicKeyInfo();
        return new CompanionPeerIdentity(
            Guid.NewGuid(),
            Convert.ToHexString(SHA256.HashData(publicKey)),
            Convert.ToBase64String(publicKey));
    }

    private sealed class TestProtector : IDataProtector
    {
        public byte[] Protect(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> entropy) => Transform(plaintext, entropy);

        public byte[] Unprotect(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> entropy) => Transform(ciphertext, entropy);

        private static byte[] Transform(ReadOnlySpan<byte> input, ReadOnlySpan<byte> entropy)
        {
            var key = SHA256.HashData(entropy);
            var result = new byte[input.Length];
            for (var index = 0; index < input.Length; index++)
            {
                result[index] = (byte)(input[index] ^ key[index % key.Length]);
            }

            return result;
        }
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"jts-companion-identity-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
