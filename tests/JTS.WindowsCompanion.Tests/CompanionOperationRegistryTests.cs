using System.Security.Cryptography;
using JTS.WindowsCompanion.Agent;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.Tests;

public sealed class CompanionOperationRegistryTests
{
    [Fact]
    public void ExactCancellationRequiresTheSameLiveSessionOwner()
    {
        using var peer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = peer.ExportSubjectPublicKeyInfo();
        var firstSession = new CompanionFrameAuthenticationContext(
            SHA256.HashData("first-session"u8),
            publicKey);
        var secondSession = new CompanionFrameAuthenticationContext(
            SHA256.HashData("second-session"u8),
            publicKey);
        var firstOwner = firstSession.DeriveOperationOwnerKey();
        var secondOwner = secondSession.DeriveOperationOwnerKey();
        var requestId = Guid.NewGuid();
        var registry = new CompanionOperationRegistry();
        using var operation = registry.Register(
            requestId,
            firstOwner,
            deadlineUnixMilliseconds: null,
            CancellationToken.None);

        Assert.False(registry.Cancel(secondOwner, requestId));
        Assert.False(operation.CancellationToken.IsCancellationRequested);
        Assert.True(registry.Cancel(firstOwner, requestId));
        Assert.True(operation.CancellationToken.IsCancellationRequested);
        Assert.Equal(
            CompanionOperationCancellationReason.RequestCancelled,
            operation.CancellationReason);
        Assert.False(registry.Cancel(firstOwner, Guid.NewGuid()));
    }

    [Fact]
    public async Task OwnerDrainCancelsWaitsAndBlocksNewWorkUntilReleased()
    {
        var registry = new CompanionOperationRegistry();
        var owner = Owner("authorized-session");
        using var first = registry.Register(
            Guid.NewGuid(),
            owner,
            deadlineUnixMilliseconds: null,
            CancellationToken.None);
        using var second = registry.Register(
            Guid.NewGuid(),
            owner,
            deadlineUnixMilliseconds: null,
            CancellationToken.None);

        var blockTask = registry.BlockOwnerAndDrainAsync(
            owner,
            excludingRequestId: Guid.Empty,
            cancellationToken: CancellationToken.None).AsTask();
        Assert.True(first.CancellationToken.IsCancellationRequested);
        Assert.True(second.CancellationToken.IsCancellationRequested);
        Assert.False(blockTask.IsCompleted);

        first.Dispose();
        second.Dispose();
        using var ownerBlock = await blockTask;
        Assert.Throws<CompanionProtocolException>(() => registry.Register(
            Guid.NewGuid(),
            owner,
            deadlineUnixMilliseconds: null,
            CancellationToken.None));

        ownerBlock.Dispose();
        using var accepted = registry.Register(
            Guid.NewGuid(),
            owner,
            deadlineUnixMilliseconds: null,
            CancellationToken.None);
        Assert.False(accepted.CancellationToken.IsCancellationRequested);
    }

    [Fact]
    public void DeadlineAndDisconnectHaveDeterministicCancellationReasons()
    {
        var now = new DateTimeOffset(2026, 7, 15, 10, 0, 0, TimeSpan.Zero);
        var timeProvider = new ManualTimeProvider(now);
        var registry = new CompanionOperationRegistry(timeProvider);
        using var connection = new CancellationTokenSource();
        using var deadlineOperation = registry.Register(
            Guid.NewGuid(),
            Owner("deadline-owner"),
            now.AddSeconds(2).ToUnixTimeMilliseconds(),
            connection.Token);
        using var disconnectedOperation = registry.Register(
            Guid.NewGuid(),
            Owner("disconnect-owner"),
            deadlineUnixMilliseconds: null,
            connection.Token);

        timeProvider.Advance(TimeSpan.FromMilliseconds(1_999));
        Assert.False(deadlineOperation.CancellationToken.IsCancellationRequested);
        timeProvider.Advance(TimeSpan.FromMilliseconds(1));
        Assert.True(deadlineOperation.CancellationToken.IsCancellationRequested);
        Assert.Equal(
            CompanionOperationCancellationReason.DeadlineExceeded,
            deadlineOperation.CancellationReason);

        connection.Cancel();
        Assert.True(disconnectedOperation.CancellationToken.IsCancellationRequested);
        Assert.Equal(
            CompanionOperationCancellationReason.ConnectionClosed,
            disconnectedOperation.CancellationReason);
        Assert.Equal(
            CompanionOperationCancellationReason.DeadlineExceeded,
            deadlineOperation.CancellationReason);
    }

    [Fact]
    public void MaximumWireDeadlineIsSafelyScheduledWithoutOverflow()
    {
        var now = new DateTimeOffset(2026, 7, 15, 10, 0, 0, TimeSpan.Zero);
        var timeProvider = new ManualTimeProvider(now);
        var registry = new CompanionOperationRegistry(timeProvider);
        using var operation = registry.Register(
            Guid.NewGuid(),
            Owner("far-future-owner"),
            long.MaxValue,
            CancellationToken.None);

        timeProvider.Advance(TimeSpan.FromDays(24));
        Assert.False(operation.CancellationToken.IsCancellationRequested);
        Assert.Equal(
            CompanionOperationCancellationReason.None,
            operation.CancellationReason);
    }

    [Fact]
    public async Task CancelOwnerDrainsOnlyMatchingOwner()
    {
        var registry = new CompanionOperationRegistry();
        var owner = Owner("manual-owner");
        var otherOwner = Owner("other-owner");
        using var matching = registry.Register(
            Guid.NewGuid(),
            owner,
            deadlineUnixMilliseconds: null,
            CancellationToken.None);
        using var unrelated = registry.Register(
            Guid.NewGuid(),
            otherOwner,
            deadlineUnixMilliseconds: null,
            CancellationToken.None);

        var cancellation = registry.CancelOwnerAndDrainAsync(
            owner,
            CompanionOperationCancellationReason.RequestCancelled,
            excludingRequestId: null,
            cancellationToken: CancellationToken.None).AsTask();
        Assert.True(matching.CancellationToken.IsCancellationRequested);
        Assert.False(unrelated.CancellationToken.IsCancellationRequested);
        Assert.False(cancellation.IsCompleted);

        matching.Dispose();
        Assert.Equal(1, await cancellation);
    }

    private static string Owner(string value)
    {
        using var peer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var context = new CompanionFrameAuthenticationContext(
            SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value)),
            peer.ExportSubjectPublicKeyInfo());
        return context.DeriveOperationOwnerKey();
    }
}
