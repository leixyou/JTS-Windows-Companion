using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Security;
using JTS.WindowsCompanion.Windows.Security;

namespace JTS.WindowsCompanion.Tests;

public sealed class DelegatedEnrollmentPersistenceTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    [Fact]
    public async Task SameRequestPreservesOriginalReceiptAndConflictingGrantCannotReplaceIt()
    {
        using var directory = new TemporaryDirectory();
        using var windows = new Identity();
        using var mac = new Identity();
        var grant = Grant(windows, mac);
        var path = Path.Combine(directory.Path, "peer.json");
        using var store = new DpapiCompanionPeerStore(path, new Protector());
        Assert.True((await store.EnrollDelegatedAsync(grant, default)).Created);
        var repeated = await store.EnrollDelegatedAsync(grant with
        {
            ApprovedAtUtc = Now.AddSeconds(1),
            ConsentReceipt = grant.ConsentReceipt! with { ApprovedAtUtc = Now.AddSeconds(1), WindowsSessionId = 8 },
        }, default);
        Assert.False(repeated.Created);
        Assert.Equal(grant, repeated.Grant);
        Assert.Equal("DELEGATION_GRANT_CONFLICT", (await Assert.ThrowsAsync<CompanionProtocolException>(() =>
            store.EnrollDelegatedAsync(grant with { ConsentReceipt = grant.ConsentReceipt! with { GrantId = Guid.NewGuid() } }, default).AsTask())).Code);
        using var differentMac = new Identity();
        Assert.Equal("PAIRING_IDENTITY_MISMATCH", (await Assert.ThrowsAsync<CompanionProtocolException>(() =>
            store.EnrollDelegatedAsync(Grant(windows, differentMac), default).AsTask())).Code);
        Assert.Equal(grant, await store.LoadAsync(default));
        var disk = await File.ReadAllTextAsync(path);
        Assert.DoesNotContain(grant.ConsentReceipt!.GrantId.ToString(), disk, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(grant.Identity.PublicKeyBase64, disk, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RevocationChecksExactGrantAndPersistsTombstoneAcrossRestart()
    {
        using var directory = new TemporaryDirectory();
        using var windows = new Identity();
        using var mac = new Identity();
        var path = Path.Combine(directory.Path, "peer.json");
        var grant = Grant(windows, mac);
        using (var store = new DpapiCompanionPeerStore(path, new Protector()))
        {
            await store.EnrollDelegatedAsync(grant, default);
            var before = await File.ReadAllBytesAsync(path);
            Assert.Equal("DELEGATION_GRANT_MISMATCH", (await Assert.ThrowsAsync<CompanionProtocolException>(() =>
                store.RevokeDelegatedAsync(Guid.NewGuid(), default).AsTask())).Code);
            Assert.Equal(before, await File.ReadAllBytesAsync(path));
            await store.RevokeDelegatedAsync(grant.ConsentReceipt!.GrantId, default);
            Assert.Null(await store.LoadAsync(default));
        }
        using var reopened = new DpapiCompanionPeerStore(path, new Protector());
        Assert.Null(await reopened.LoadAsync(default));
        Assert.Equal("DELEGATION_REVOKED", (await Assert.ThrowsAsync<CompanionProtocolException>(() =>
            reopened.EnrollDelegatedAsync(grant, default).AsTask())).Code);
        var replacement = Grant(windows, mac);
        Assert.True((await reopened.EnrollDelegatedAsync(replacement, default)).Created);
        Assert.Equal(replacement, await reopened.LoadAsync(default));
    }

    [Fact]
    public async Task ConcurrentIndependentStoresCannotOverwriteDifferentEnrollments()
    {
        using var directory = new TemporaryDirectory();
        using var windows = new Identity();
        using var firstMac = new Identity();
        using var secondMac = new Identity();
        var first = Grant(windows, firstMac);
        var second = Grant(windows, secondMac);
        var path = Path.Combine(directory.Path, "peer.json");
        using var firstStore = new DpapiCompanionPeerStore(path, new Protector());
        using var secondStore = new DpapiCompanionPeerStore(path, new Protector());
        async Task<bool> Attempt(DpapiCompanionPeerStore store, CompanionPeerGrant grant)
        {
            try { return (await store.EnrollDelegatedAsync(grant, default)).Created; }
            catch (CompanionProtocolException error) when (error.Code == "PAIRING_IDENTITY_MISMATCH") { return false; }
        }
        var outcomes = await Task.WhenAll(Task.Run(() => Attempt(firstStore, first)), Task.Run(() => Attempt(secondStore, second)));
        Assert.Single(outcomes, value => value);
        Assert.Equal(outcomes[0] ? first : second, await firstStore.LoadAsync(default));
    }

    [Fact]
    public async Task FailedProtectionNeverPublishesGrantOrLosesExistingGrantOnRevoke()
    {
        using var directory = new TemporaryDirectory();
        using var windows = new Identity();
        using var mac = new Identity();
        var path = Path.Combine(directory.Path, "peer.json");
        var protector = new Protector { FailProtect = true };
        var grant = Grant(windows, mac);
        using var store = new DpapiCompanionPeerStore(path, protector);
        await Assert.ThrowsAsync<CryptographicException>(() => store.EnrollDelegatedAsync(grant, default).AsTask());
        Assert.False(File.Exists(path));
        protector.FailProtect = false;
        await store.EnrollDelegatedAsync(grant, default);
        var before = await File.ReadAllBytesAsync(path);
        protector.FailProtect = true;
        await Assert.ThrowsAsync<CryptographicException>(() => store.RevokeDelegatedAsync(grant.ConsentReceipt!.GrantId, default).AsTask());
        Assert.Equal(before, await File.ReadAllBytesAsync(path));
        Assert.Equal(grant, await store.LoadAsync(default));
    }

    [Fact]
    public async Task LegacyV1GrantRemainsReadableAndIsNeverRelabeledAsDelegated()
    {
        using var directory = new TemporaryDirectory();
        using var windows = new Identity();
        using var mac = new Identity();
        var legacy = new CompanionPeerGrant(mac.Peer, Now);
        var path = Path.Combine(directory.Path, "peer.json");
        var protector = new Protector();
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(legacy, ControlMessageSerializer.Options);
        var protectedBytes = protector.Protect(plaintext, SHA256.HashData(Encoding.UTF8.GetBytes("JTS.WindowsCompanion.PairedPeer.v1")));
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new { version = 1, protectedGrantBase64 = Convert.ToBase64String(protectedBytes) }));
        using var store = new DpapiCompanionPeerStore(path, protector);
        Assert.Equal(legacy, await store.LoadAsync(default));
        var session = new CompanionAuthorizationSession(windows, store, new NoPrompt(), () => Now);
        var hello = await session.BeginHandshakeAsync(default);
        var result = await session.AuthorizeAsync(await Proof(mac, windows, hello, Now), default);
        Assert.Equal("interactive", result.AuthorizationSource);
        Assert.Null(result.DelegationGrantId);
        Assert.Equal("DELEGATION_GRANT_CONFLICT", (await Assert.ThrowsAsync<CompanionProtocolException>(() =>
            store.EnrollDelegatedAsync(Grant(windows, mac), default).AsTask())).Code);
    }

    [Fact]
    public async Task DelegatedGrantStillRequiresFreshValidProofAndUnpairRevokesAcrossRestart()
    {
        using var directory = new TemporaryDirectory();
        using var windows = new Identity();
        using var mac = new Identity();
        var grant = Grant(windows, mac);
        var path = Path.Combine(directory.Path, "peer.json");
        using var store = new DpapiCompanionPeerStore(path, new Protector());
        await store.EnrollDelegatedAsync(grant, default);
        // The import deadline is over, but persisted permission is still valid.
        var nextDay = Now.AddDays(1);
        var session = new CompanionAuthorizationSession(windows, store, new NoPrompt(), () => nextDay);
        Assert.False(session.IsAuthorized);
        var hello = await session.BeginHandshakeAsync(default);
        Assert.False(hello.PairingRequired);
        var bad = await Proof(mac, windows, hello, nextDay);
        var signature = Convert.FromBase64String(bad.SignatureBase64);
        signature[0] ^= 1;
        await Assert.ThrowsAsync<CompanionProtocolException>(() => session.AuthorizeAsync(bad with
            { SignatureBase64 = Convert.ToBase64String(signature) }, default).AsTask());
        Assert.False(session.IsAuthorized);
        hello = await session.BeginHandshakeAsync(default);
        var authorized = await session.AuthorizeAsync(await Proof(mac, windows, hello, nextDay), default);
        Assert.True(authorized.Authorized);
        Assert.Equal("ownerDelegated", authorized.AuthorizationSource);
        Assert.Equal(grant.ConsentReceipt!.GrantId, authorized.DelegationGrantId);
        await session.RevokeAsync(default);
        Assert.False(session.IsAuthorized);
        Assert.False(session.HasPersistedPeer);
        Assert.False(session.TryGetAuthorizedPeerContext(out _));
        using var restarted = new DpapiCompanionPeerStore(path, new Protector());
        var newSession = new CompanionAuthorizationSession(windows, restarted, new NoPrompt(), () => nextDay);
        Assert.True((await newSession.BeginHandshakeAsync(default)).PairingRequired);
        Assert.Equal("DELEGATION_REVOKED", (await Assert.ThrowsAsync<CompanionProtocolException>(() =>
            restarted.EnrollDelegatedAsync(grant, default).AsTask())).Code);
    }

    [Fact]
    public async Task NewSessionRequiresNewChallengeForPersistedDelegation()
    {
        using var directory = new TemporaryDirectory();
        using var windows = new Identity();
        using var mac = new Identity();
        using var store = new DpapiCompanionPeerStore(Path.Combine(directory.Path, "peer.json"), new Protector());
        var grant = Grant(windows, mac);
        await store.EnrollDelegatedAsync(grant, default);
        var first = new CompanionAuthorizationSession(windows, store, new NoPrompt(), () => Now);
        var firstHello = await first.BeginHandshakeAsync(default);
        var previousProof = await Proof(mac, windows, firstHello, Now);
        Assert.True((await first.AuthorizeAsync(previousProof, default)).Authorized);
        first.ResetSession();
        Assert.False(first.IsAuthorized);
        var second = new CompanionAuthorizationSession(windows, store, new NoPrompt(), () => Now);
        Assert.False(second.IsAuthorized);
        var newHello = await second.BeginHandshakeAsync(default);
        Assert.NotEqual(firstHello.ChallengeBase64, newHello.ChallengeBase64);
        await Assert.ThrowsAsync<CompanionProtocolException>(() => second.AuthorizeAsync(previousProof, default).AsTask());
        Assert.False(second.IsAuthorized);
        newHello = await second.BeginHandshakeAsync(default);
        var authorized = await second.AuthorizeAsync(await Proof(mac, windows, newHello, Now), default);
        Assert.Equal(grant.ConsentReceipt!.GrantId, authorized.DelegationGrantId);
        Assert.Equal(grant, await store.LoadAsync(default));
    }

    [Fact]
    public async Task StoredDelegationCannotFollowAChangedWindowsIdentity()
    {
        using var directory = new TemporaryDirectory();
        using var windows = new Identity();
        using var changedWindows = new Identity();
        using var mac = new Identity();
        using var store = new DpapiCompanionPeerStore(Path.Combine(directory.Path, "peer.json"), new Protector());
        await store.EnrollDelegatedAsync(Grant(windows, mac), default);
        var session = new CompanionAuthorizationSession(changedWindows, store, new NoPrompt(), () => Now);
        var hello = await session.BeginHandshakeAsync(default);
        var proof = await Proof(mac, changedWindows, hello, Now);
        var failure = await Assert.ThrowsAsync<CompanionProtocolException>(() => session.AuthorizeAsync(proof, default).AsTask());
        Assert.Equal("DELEGATED_ENROLLMENT_WINDOWS_MISMATCH", failure.Code);
        Assert.False(session.IsAuthorized);
    }

    [Fact]
    public async Task ExistingIdentityLookupNeverCreatesMissingOrRepairsCorruptIdentity()
    {
        using var directory = new TemporaryDirectory();
        var path = Path.Combine(directory.Path, "identity.json");
        using var identity = new DpapiCompanionIdentity(path, new Protector());
        await Assert.ThrowsAnyAsync<IOException>(() => identity.GetExistingMetadataAsync(default).AsTask());
        Assert.False(File.Exists(path));
        await File.WriteAllTextAsync(path, "corrupt");
        await Assert.ThrowsAnyAsync<Exception>(() => identity.GetExistingMetadataAsync(default).AsTask());
        Assert.Equal("corrupt", await File.ReadAllTextAsync(path));
    }

    [Fact]
    public void WindowsBindingMismatchAndExpiredImportCannotCreateAReceipt()
    {
        using var windows = new Identity();
        using var otherWindows = new Identity();
        using var mac = new Identity();
        var request = Request(windows, mac);
        Assert.Throws<CompanionProtocolException>(() => WindowsDelegatedEnrollment.CreateGrant(request, new string('A', 64), otherWindows.Metadata, "S-1-5-21-42", 1, Now));
        Assert.Throws<CompanionProtocolException>(() => WindowsDelegatedEnrollment.CreateGrant(request, new string('A', 64), windows.Metadata, "S-1-5-21-42", 1, Now.AddHours(1)));
    }

    private static CompanionPeerGrant Grant(Identity windows, Identity mac) => WindowsDelegatedEnrollment.CreateGrant(
        Request(windows, mac), new string('A', 64), windows.Metadata, "S-1-5-21-42", 2, Now);

    private static CompanionDelegatedEnrollmentRequest Request(Identity windows, Identity mac) => new(
        1, Guid.NewGuid(), "ownerDelegated", Guid.NewGuid(), "rdp://192.0.2.10:3389/example-user", mac.Peer,
        new(windows.Metadata.DeviceId, windows.Metadata.FingerprintSha256), Now.AddMinutes(-1), Now.AddMinutes(10), "device-ai-control-enabled");

    private static ValueTask<ClientAuthorizationProof> Proof(Identity mac, Identity windows, CompanionAuthorizationChallenge hello, DateTimeOffset now) =>
        ClientAuthorizationProofService.CreateAsync(mac, windows.Metadata.DeviceId, Convert.FromBase64String(hello.ChallengeBase64), 1, now, default);

    private sealed class NoPrompt : ICompanionPairingConsentPrompt
    {
        public ValueTask<bool> ConfirmAsync(CompanionPeerIdentity peer, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("A stored grant must not display another consent dialog.");
    }

    private sealed class Identity : ICompanionIdentity, IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public CompanionIdentityMetadata Metadata { get; }
        public CompanionPeerIdentity Peer => new(Metadata.DeviceId, Metadata.FingerprintSha256, Metadata.PublicKeyBase64);
        public Identity()
        {
            var bytes = _key.ExportSubjectPublicKeyInfo();
            Metadata = new(Guid.NewGuid(), Convert.ToHexString(SHA256.HashData(bytes)), Convert.ToBase64String(bytes));
        }
        public ValueTask<CompanionIdentityMetadata> GetMetadataAsync(CancellationToken cancellationToken) => ValueTask.FromResult(Metadata);
        public ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken) => ValueTask.FromResult(_key.SignData(payload.Span, HashAlgorithmName.SHA256));
        public void Dispose() => _key.Dispose();
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "jts-delegation-" + Guid.NewGuid().ToString("N"));
        public TemporaryDirectory() => Directory.CreateDirectory(Path);
        public void Dispose() => Directory.Delete(Path, recursive: true);
    }

    private sealed class Protector : IDataProtector
    {
        public bool FailProtect { get; set; }
        public byte[] Protect(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> entropy) =>
            FailProtect ? throw new CryptographicException("Injected failure") : Transform(plaintext, entropy);
        public byte[] Unprotect(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> entropy) => Transform(ciphertext, entropy);
        private static byte[] Transform(ReadOnlySpan<byte> data, ReadOnlySpan<byte> entropy)
        {
            var bytes = data.ToArray();
            for (var index = 0; index < bytes.Length; index++) bytes[index] ^= entropy[index % entropy.Length];
            return bytes;
        }
    }
}
