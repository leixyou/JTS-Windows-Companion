using System.Security.Cryptography;
using JTS.WindowsCompanion.Elevation;
using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.Tests;

public sealed class SecurityTests
{
    [Fact]
    public async Task PairingProof_BindsIdentityChallengeSequenceAndTime()
    {
        using var identity = new TestIdentity();
        var now = DateTimeOffset.UtcNow;
        var challenge = RandomNumberGenerator.GetBytes(32);
        var proof = await PairingProofService.CreateAsync(identity, challenge, 7, now, CancellationToken.None);

        Assert.True(PairingProofService.Verify(proof, TimeSpan.FromMinutes(2), now));
        Assert.False(PairingProofService.Verify(proof with { Sequence = 8 }, TimeSpan.FromMinutes(2), now));
        Assert.False(PairingProofService.Verify(proof, TimeSpan.FromSeconds(1), now.AddSeconds(2)));
    }

    [Fact]
    public void ElevationLease_RequiresExplicitConsentAndExactPayload()
    {
        var timeProvider = new ManualTimeProvider(DateTimeOffset.UtcNow);
        using var manager = new ElevationLeaseManager(timeProvider);
        var payload = "approved-script"u8.ToArray();
        var action = new ElevatedActionGrant(
            "install-package",
            ElevatedActionKind.ApprovedPowerShell,
            Convert.ToHexString(SHA256.HashData(payload)),
            "Install the approved local package");
        var request = new ElevationLeaseRequest(Guid.NewGuid(), TimeSpan.FromMinutes(5), [action]);

        Assert.Throws<UnauthorizedAccessException>(() => manager.IssueApproved(request, userConfirmedOnSecureDesktop: false));
        var lease = manager.IssueApproved(request, userConfirmedOnSecureDesktop: true);
        manager.Authorize(lease.LeaseId, action.ActionId, action.Kind, payload);

        Assert.Throws<UnauthorizedAccessException>(() =>
            manager.Authorize(lease.LeaseId, action.ActionId, action.Kind, "changed"u8));
        timeProvider.Advance(TimeSpan.FromMinutes(6));
        Assert.Throws<UnauthorizedAccessException>(() =>
            manager.Authorize(lease.LeaseId, action.ActionId, action.Kind, payload));
    }

    [Fact]
    public void ElevationLease_EnforcesFifteenMinuteMaximum()
    {
        using var manager = new ElevationLeaseManager();
        var request = new ElevationLeaseRequest(
            Guid.NewGuid(),
            TimeSpan.FromMinutes(16),
            [new ElevatedActionGrant(
                "operation",
                ElevatedActionKind.WorkerOperation,
                new string('A', 64),
                "Run the fixed operation")]);

        Assert.Throws<ArgumentException>(() => manager.IssueApproved(request, userConfirmedOnSecureDesktop: true));
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

        public ValueTask<CompanionIdentityMetadata> GetMetadataAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(_metadata);

        public ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken) =>
            ValueTask.FromResult(_key.SignData(payload.Span, HashAlgorithmName.SHA256));

        public void Dispose() => _key.Dispose();
    }

}
