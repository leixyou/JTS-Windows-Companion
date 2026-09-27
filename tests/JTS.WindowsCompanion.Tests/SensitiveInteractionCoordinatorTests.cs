using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.Tests;

public sealed class SensitiveInteractionCoordinatorTests
{
    [Fact]
    public void BarrierFailsFastAndNeverQueuesBehindHumanPrompt()
    {
        var coordinator = new CompanionSensitiveInteractionCoordinator();
        using var pairing = coordinator.Enter(CompanionSensitiveInteractionKind.Pairing);

        var failure = Assert.Throws<CompanionProtocolException>(() =>
            coordinator.Enter(CompanionSensitiveInteractionKind.DesktopAutomation));

        Assert.Equal("SENSITIVE_INTERACTION_ACTIVE", failure.Code);
        Assert.True(coordinator.IsActive);
        Assert.Equal(CompanionSensitiveInteractionKind.Pairing, coordinator.ActiveKind);
    }

    [Fact]
    public void DisposingLeaseExactlyOnceReleasesBarrier()
    {
        var coordinator = new CompanionSensitiveInteractionCoordinator();
        var elevation = coordinator.Enter(CompanionSensitiveInteractionKind.ElevationPrompt);

        elevation.Dispose();
        elevation.Dispose();
        using var mutation = coordinator.Enter(CompanionSensitiveInteractionKind.ShellMutation);

        Assert.Equal(CompanionSensitiveInteractionKind.ShellMutation, coordinator.ActiveKind);
    }

    [Fact]
    public async Task ConcurrentMutationCannotEnterUntilCurrentOperationCompletes()
    {
        var coordinator = new CompanionSensitiveInteractionCoordinator();
        using var active = coordinator.Enter(CompanionSensitiveInteractionKind.WorkerMutation);

        var failure = await Task.Run(() => Assert.Throws<CompanionProtocolException>(() =>
            coordinator.Enter(CompanionSensitiveInteractionKind.FileMutation)));

        Assert.Equal("SENSITIVE_INTERACTION_ACTIVE", failure.Code);
    }
}
