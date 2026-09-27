using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Agent;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.Tests;

public sealed class CompanionAuthorizationTests
{
    [Fact]
    public async Task ClientProof_BindsBothDevicesChallengeSequenceAndTime()
    {
        using var windowsIdentity = new TestIdentity();
        using var clientIdentity = new TestIdentity();
        var now = DateTimeOffset.UtcNow;
        var challenge = RandomNumberGenerator.GetBytes(CompanionAuthorizationSession.ChallengeBytes);
        var windows = await windowsIdentity.GetMetadataAsync(CancellationToken.None);
        var proof = await ClientAuthorizationProofService.CreateAsync(
            clientIdentity,
            windows.DeviceId,
            challenge,
            17,
            now,
            CancellationToken.None);

        var peer = ClientAuthorizationProofService.Validate(
            proof,
            windows.DeviceId,
            challenge,
            TimeSpan.FromMinutes(2),
            now);

        Assert.Equal(proof.DeviceId, peer.DeviceId);
        Assert.Equal(proof.FingerprintSha256, peer.FingerprintSha256);
        Assert.Equal(64, Convert.FromBase64String(proof.SignatureBase64).Length);
        Assert.Equal(
            "PAIRING_SIGNATURE_INVALID",
            Assert.Throws<CompanionProtocolException>(() =>
                ClientAuthorizationProofService.Validate(
                    proof with { Sequence = 18 },
                    windows.DeviceId,
                    challenge,
                    TimeSpan.FromMinutes(2),
                    now)).Code);
        Assert.Equal(
            "PAIRING_SIGNATURE_INVALID",
            Assert.Throws<CompanionProtocolException>(() =>
                ClientAuthorizationProofService.Validate(
                    proof,
                    Guid.NewGuid(),
                    challenge,
                    TimeSpan.FromMinutes(2),
                    now)).Code);
        Assert.Equal(
            "PAIRING_CHALLENGE_MISMATCH",
            Assert.Throws<CompanionProtocolException>(() =>
                ClientAuthorizationProofService.Validate(
                    proof,
                    windows.DeviceId,
                    RandomNumberGenerator.GetBytes(CompanionAuthorizationSession.ChallengeBytes),
                    TimeSpan.FromMinutes(2),
                    now)).Code);
        Assert.Equal(
            "PAIRING_PROOF_EXPIRED",
            Assert.Throws<CompanionProtocolException>(() =>
                ClientAuthorizationProofService.Validate(
                    proof,
                    windows.DeviceId,
                    challenge,
                    TimeSpan.FromMinutes(2),
                    now.AddMinutes(3))).Code);
        Assert.Equal(
            "CLIENT_PROOF_INVALID",
            Assert.Throws<CompanionProtocolException>(() =>
                ClientAuthorizationProofService.Validate(
                    proof with { ChallengeBase64 = null! },
                    windows.DeviceId,
                    challenge,
                    TimeSpan.FromMinutes(2),
                    now)).Code);
        Assert.Equal(
            "CLIENT_IDENTITY_INVALID",
            Assert.Throws<CompanionProtocolException>(() =>
                ClientAuthorizationProofService.Validate(
                    proof with { FingerprintSha256 = null! },
                    windows.DeviceId,
                    challenge,
                    TimeSpan.FromMinutes(2),
                    now)).Code);
    }

    [Fact]
    public async Task FirstPairingRequiresConsentAndMatchingPeerCanReauthenticate()
    {
        using var windowsIdentity = new TestIdentity();
        using var clientIdentity = new TestIdentity();
        var now = DateTimeOffset.UtcNow;
        var store = new MemoryPeerStore();
        var consent = new RecordingConsentPrompt(approved: true);
        var session = new CompanionAuthorizationSession(
            windowsIdentity,
            store,
            consent,
            () => now);

        var firstChallenge = await session.BeginHandshakeAsync(CancellationToken.None);
        Assert.True(firstChallenge.PairingRequired);
        var first = await session.AuthorizeAsync(
            await CreateProofAsync(clientIdentity, windowsIdentity, firstChallenge, 1, now),
            CancellationToken.None);

        Assert.True(first.Authorized);
        Assert.True(first.NewlyPaired);
        Assert.True(session.IsAuthorized);
        Assert.True(session.HasPersistedPeer);
        Assert.Equal(1, consent.CallCount);
        Assert.NotNull(store.Grant);

        var liveRehandshake = await Assert.ThrowsAsync<CompanionProtocolException>(() =>
            session.BeginHandshakeAsync(CancellationToken.None).AsTask());
        Assert.Equal("PAIRING_ALREADY_AUTHORIZED", liveRehandshake.Code);
        Assert.True(session.IsAuthorized);

        session.ResetSession();
        var secondChallenge = await session.BeginHandshakeAsync(CancellationToken.None);
        Assert.False(session.IsAuthorized);
        Assert.False(secondChallenge.PairingRequired);
        var second = await session.AuthorizeAsync(
            await CreateProofAsync(clientIdentity, windowsIdentity, secondChallenge, 2, now),
            CancellationToken.None);

        Assert.True(second.Authorized);
        Assert.False(second.NewlyPaired);
        Assert.True(session.IsAuthorized);
        Assert.Equal(1, consent.CallCount);
    }

    [Fact]
    public async Task MismatchedPeerIsRejectedWithoutPromptOrGrantReplacement()
    {
        using var windowsIdentity = new TestIdentity();
        using var approvedClient = new TestIdentity();
        using var differentClient = new TestIdentity();
        var now = DateTimeOffset.UtcNow;
        var store = new MemoryPeerStore();
        var consent = new RecordingConsentPrompt(approved: true);
        var session = new CompanionAuthorizationSession(
            windowsIdentity,
            store,
            consent,
            () => now);
        var firstChallenge = await session.BeginHandshakeAsync(CancellationToken.None);
        await session.AuthorizeAsync(
            await CreateProofAsync(approvedClient, windowsIdentity, firstChallenge, 1, now),
            CancellationToken.None);
        var approvedGrant = store.Grant;

        session.ResetSession();
        var secondChallenge = await session.BeginHandshakeAsync(CancellationToken.None);
        var exception = await Assert.ThrowsAsync<CompanionProtocolException>(async () =>
            await session.AuthorizeAsync(
                await CreateProofAsync(differentClient, windowsIdentity, secondChallenge, 2, now),
                CancellationToken.None));

        Assert.Equal("PAIRING_IDENTITY_MISMATCH", exception.Code);
        Assert.False(session.IsAuthorized);
        Assert.Equal(1, consent.CallCount);
        Assert.Equal(approvedGrant, store.Grant);
    }

    [Fact]
    public async Task DeclinedPairingDoesNotPersistOrAuthorizeClient()
    {
        using var windowsIdentity = new TestIdentity();
        using var clientIdentity = new TestIdentity();
        var now = DateTimeOffset.UtcNow;
        var store = new MemoryPeerStore();
        var session = new CompanionAuthorizationSession(
            windowsIdentity,
            store,
            new RecordingConsentPrompt(approved: false),
            () => now);
        var challenge = await session.BeginHandshakeAsync(CancellationToken.None);

        var exception = await Assert.ThrowsAsync<CompanionProtocolException>(async () =>
            await session.AuthorizeAsync(
                await CreateProofAsync(clientIdentity, windowsIdentity, challenge, 1, now),
                CancellationToken.None));

        Assert.Equal("PAIRING_DECLINED", exception.Code);
        Assert.False(session.IsAuthorized);
        Assert.Null(store.Grant);
    }

    [Fact]
    public async Task AuthorizationChallengeIsSingleUseAndExpiresClosed()
    {
        using var windowsIdentity = new TestIdentity();
        using var clientIdentity = new TestIdentity();
        var now = DateTimeOffset.UtcNow;
        var current = now;
        var session = new CompanionAuthorizationSession(
            windowsIdentity,
            new MemoryPeerStore(),
            new RecordingConsentPrompt(approved: true),
            () => current);
        var challenge = await session.BeginHandshakeAsync(CancellationToken.None);
        var proof = await CreateProofAsync(clientIdentity, windowsIdentity, challenge, 1, now);
        await session.AuthorizeAsync(proof, CancellationToken.None);

        var replay = await Assert.ThrowsAsync<CompanionProtocolException>(async () =>
            await session.AuthorizeAsync(proof, CancellationToken.None));
        Assert.Equal("PAIRING_HELLO_REQUIRED", replay.Code);

        session.ResetSession();
        var expiringChallenge = await session.BeginHandshakeAsync(CancellationToken.None);
        current = now.Add(CompanionAuthorizationSession.ChallengeLifetime).AddSeconds(1);
        var expired = await Assert.ThrowsAsync<CompanionProtocolException>(async () =>
            await session.AuthorizeAsync(
                await CreateProofAsync(clientIdentity, windowsIdentity, expiringChallenge, 2, current),
                CancellationToken.None));
        Assert.Equal("PAIRING_CHALLENGE_EXPIRED", expired.Code);
        Assert.False(session.IsAuthorized);
    }

    [Fact]
    public async Task SessionResetWhileConsentIsPendingSupersedesAuthorizationWithoutPersisting()
    {
        using var windowsIdentity = new TestIdentity();
        using var clientIdentity = new TestIdentity();
        var now = DateTimeOffset.UtcNow;
        var store = new MemoryPeerStore();
        var consent = new BlockingConsentPrompt();
        var session = new CompanionAuthorizationSession(
            windowsIdentity,
            store,
            consent,
            () => now);
        var challenge = await session.BeginHandshakeAsync(CancellationToken.None);
        var authorization = session.AuthorizeAsync(
            await CreateProofAsync(clientIdentity, windowsIdentity, challenge, 1, now),
            CancellationToken.None).AsTask();
        await consent.WaitUntilPromptedAsync();

        session.ResetSession();
        consent.Complete(approved: true);

        var exception = await Assert.ThrowsAsync<CompanionProtocolException>(() => authorization);
        Assert.Equal("PAIRING_CHALLENGE_SUPERSEDED", exception.Code);
        Assert.False(session.IsAuthorized);
        Assert.Null(store.Grant);
    }

    [Fact]
    public async Task AuthorizedPeerCanRevokeGrantAndImmediatelyLosesAccess()
    {
        using var windowsIdentity = new TestIdentity();
        using var clientIdentity = new TestIdentity();
        var now = DateTimeOffset.UtcNow;
        var store = new MemoryPeerStore();
        var session = new CompanionAuthorizationSession(
            windowsIdentity,
            store,
            new RecordingConsentPrompt(approved: true),
            () => now);
        var challenge = await session.BeginHandshakeAsync(CancellationToken.None);
        await session.AuthorizeAsync(
            await CreateProofAsync(clientIdentity, windowsIdentity, challenge, 1, now),
            CancellationToken.None);

        await session.RevokeAsync(CancellationToken.None);

        Assert.False(session.IsAuthorized);
        Assert.False(session.HasPersistedPeer);
        Assert.Null(store.Grant);
        Assert.False(session.Evaluate("uia.snapshot").Allowed);
    }

    [Fact]
    public async Task RouterDeniesStructuredMethodsBeforeHandlerAndAllowsBootstrap()
    {
        var gate = new TestAuthorizationGate(authorized: false);
        var router = new CompanionRequestRouter(gate);
        var calls = 0;
        router.Register("uia.snapshot", (_, _) =>
        {
            calls++;
            return ValueTask.FromResult<object?>(new { ok = true });
        });
        router.Register("companion.hello", (_, _) =>
            ValueTask.FromResult<object?>(new { challenge = true }));

        var denied = await router.DispatchAsync(
            Request("uia.snapshot", "same-key"),
            DateTimeOffset.UtcNow,
            CancellationToken.None);
        var bootstrap = await router.DispatchAsync(
            Request("companion.hello", "same-key"),
            DateTimeOffset.UtcNow,
            CancellationToken.None);

        Assert.Equal("PAIRING_REQUIRED", denied.Error?.Code);
        Assert.Equal(0, calls);
        Assert.True(bootstrap.Success);
    }

    [Fact]
    public async Task IdempotencyCacheIsPartitionedByPeerAndMethod()
    {
        var gate = new TestAuthorizationGate(authorizationScope: new string('A', 64));
        var router = new CompanionRequestRouter(gate);
        var calls = 0;
        router.Register("fixed.first", (_, _) =>
            ValueTask.FromResult<object?>(new { call = ++calls }));
        router.Register("fixed.second", (_, _) =>
            ValueTask.FromResult<object?>(new { call = ++calls }));

        var first = await router.DispatchAsync(
            Request("fixed.first", "shared-key"),
            DateTimeOffset.UtcNow,
            CancellationToken.None);
        var repeated = await router.DispatchAsync(
            Request("fixed.first", "shared-key"),
            DateTimeOffset.UtcNow,
            CancellationToken.None);
        gate.AuthorizationScope = new string('B', 64);
        var differentPeer = await router.DispatchAsync(
            Request("fixed.first", "shared-key"),
            DateTimeOffset.UtcNow,
            CancellationToken.None);
        var differentMethod = await router.DispatchAsync(
            Request("fixed.second", "shared-key"),
            DateTimeOffset.UtcNow,
            CancellationToken.None);

        Assert.Equal(1, first.Result?.GetProperty("call").GetInt32());
        Assert.Equal(1, repeated.Result?.GetProperty("call").GetInt32());
        Assert.Equal(2, differentPeer.Result?.GetProperty("call").GetInt32());
        Assert.Equal(3, differentMethod.Result?.GetProperty("call").GetInt32());
        Assert.Equal(3, calls);
    }

    private static async ValueTask<ClientAuthorizationProof> CreateProofAsync(
        ICompanionIdentity clientIdentity,
        ICompanionIdentity windowsIdentity,
        CompanionAuthorizationChallenge challenge,
        ulong sequence,
        DateTimeOffset now)
    {
        var windows = await windowsIdentity.GetMetadataAsync(CancellationToken.None);
        return await ClientAuthorizationProofService.CreateAsync(
            clientIdentity,
            windows.DeviceId,
            Convert.FromBase64String(challenge.ChallengeBase64),
            sequence,
            now,
            CancellationToken.None);
    }

    private static CompanionRequest Request(string method, string? idempotencyKey) => new(
        CompanionProtocol.CurrentVersion,
        Guid.NewGuid(),
        method,
        null,
        idempotencyKey,
        null,
        JsonSerializer.SerializeToElement(new { }));

    private sealed class MemoryPeerStore : ICompanionPeerStore
    {
        public CompanionPeerGrant? Grant { get; private set; }

        public ValueTask<CompanionPeerGrant?> LoadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(Grant);
        }

        public ValueTask SaveIfAbsentAsync(
            CompanionPeerGrant grant,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Grant is not null
                && !CompanionPeerIdentityValidation.Matches(Grant.Identity, grant.Identity))
            {
                throw new CompanionProtocolException(
                    "PAIRING_IDENTITY_MISMATCH",
                    "A different peer is already stored.");
            }

            Grant ??= grant;
            return ValueTask.CompletedTask;
        }

        public ValueTask ClearAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Grant = null;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class RecordingConsentPrompt : ICompanionPairingConsentPrompt
    {
        private readonly bool _approved;

        public RecordingConsentPrompt(bool approved)
        {
            _approved = approved;
        }

        public int CallCount { get; private set; }

        public ValueTask<bool> ConfirmAsync(
            CompanionPeerIdentity peer,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            return ValueTask.FromResult(_approved);
        }
    }

    private sealed class BlockingConsentPrompt : ICompanionPairingConsentPrompt
    {
        private readonly TaskCompletionSource _prompted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<bool> _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async ValueTask<bool> ConfirmAsync(
            CompanionPeerIdentity peer,
            CancellationToken cancellationToken)
        {
            _prompted.TrySetResult();
            return await _completion.Task.WaitAsync(cancellationToken);
        }

        public Task WaitUntilPromptedAsync() => _prompted.Task.WaitAsync(TimeSpan.FromSeconds(5));

        public void Complete(bool approved) => _completion.TrySetResult(approved);
    }

    private sealed class TestIdentity : ICompanionIdentity, IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly CompanionIdentityMetadata _metadata;

        public TestIdentity()
        {
            var publicKey = _key.ExportSubjectPublicKeyInfo();
            _metadata = new CompanionIdentityMetadata(
                Guid.NewGuid(),
                Convert.ToHexString(SHA256.HashData(publicKey)),
                Convert.ToBase64String(publicKey));
        }

        public ValueTask<CompanionIdentityMetadata> GetMetadataAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(_metadata);
        }

        public ValueTask<byte[]> SignAsync(
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(_key.SignData(payload.Span, HashAlgorithmName.SHA256));
        }

        public void Dispose() => _key.Dispose();
    }
}
