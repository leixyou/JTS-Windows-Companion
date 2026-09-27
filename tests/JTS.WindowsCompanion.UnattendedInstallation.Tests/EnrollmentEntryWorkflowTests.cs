using JTS.WindowsCompanion.Enrollment;
using JTS.WindowsCompanion.UnattendedSetup;
using Xunit;

namespace JTS.WindowsCompanion.UnattendedInstallation.Tests;

public sealed class EnrollmentEntryWorkflowTests
{
    private const string Code = "jts-pair://enroll?relay=https%3A%2F%2Frelay.example&id=00000000-0000-4000-8000-000000000001&key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private static readonly EnrollmentManagementStatus Pending = new("pending", "public-device", "https://relay.example", Guid.NewGuid(), null);

    [Fact]
    public async Task FreshInstallationCompletesBeforeTheCodeReachesTheService()
    {
        var installed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var events = new List<string>();
        var running = EnrollmentEntryWorkflow.EnrollAsync(Code, CompanionInstallationPresence.Absent,
            async origin => { Assert.Equal("https://relay.example/", origin); events.Add("install"); await installed.Task; events.Add("installed"); },
            (code, _) => { Assert.Equal(Code, code); events.Add("enroll"); return Task.FromResult(Pending); }, default);
        Assert.Equal(new[] { "install" }, events); Assert.False(running.IsCompleted);
        installed.SetResult();
        Assert.Equal(Pending, await running);
        Assert.Equal(new[] { "install", "installed", "enroll" }, events);
    }

    [Fact]
    public async Task InstalledComputerGoesDirectlyToProtectedManagementWithoutReinstalling()
    {
        var status = await EnrollmentEntryWorkflow.EnrollAsync(Code, CompanionInstallationPresence.Installed,
            _ => throw new InvalidOperationException("Installer must not run"), (_, _) => Task.FromResult(Pending), default);
        Assert.Equal(Pending, status);
    }

    [Fact]
    public async Task OldInstalledServiceWithoutManagementPreservesStateAndDoesNotReinstall()
    {
        var error = await Assert.ThrowsAsync<EnrollmentException>(() => EnrollmentEntryWorkflow.EnrollAsync(Code, CompanionInstallationPresence.Installed,
            _ => throw new InvalidOperationException("Installer must not run"),
            (_, _) => throw new EnrollmentException("ENROLLMENT_SERVICE_UNAVAILABLE"), default));
        Assert.Equal("ENROLLMENT_SERVICE_UNAVAILABLE", error.Code);
    }

    [Fact]
    public async Task PartialInstallationNeverWritesARequestOrStartsAnotherTransaction()
    {
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => EnrollmentEntryWorkflow.EnrollAsync(Code, CompanionInstallationPresence.NeedsReview,
            _ => throw new Exception("must not install"), (_, _) => throw new Exception("must not enroll"), default));
        Assert.Equal("INSTALL_EXISTING_STATE_REQUIRES_LOCAL_REVIEW", error.Message);
    }

    [Fact]
    public async Task InvalidCodeIsRejectedBeforeAnyLocalInstallation()
    {
        var error = await Assert.ThrowsAsync<EnrollmentException>(() => EnrollmentEntryWorkflow.EnrollAsync("private-invalid-code", CompanionInstallationPresence.Absent,
            _ => throw new Exception("must not install"), (_, _) => throw new Exception("must not enroll"), default));
        Assert.Equal("ENROLLMENT_CODE_INVALID", error.Code);
    }

    [Fact]
    public async Task FailedInstallationNeverSubmitsTheCode()
    {
        var failure = new IOException("INSTALL_ACTIVATION_REQUIRES_LOCAL_REPAIR");
        Assert.Same(failure, await Assert.ThrowsAsync<IOException>(() => EnrollmentEntryWorkflow.EnrollAsync(Code, CompanionInstallationPresence.Absent,
            _ => throw failure, (_, _) => throw new Exception("must not enroll"), default)));
    }

    [Fact]
    public async Task CancellationAfterInstallationDoesNotEnrollOrRollBackItsSavedState()
    {
        using var stop = new CancellationTokenSource(); var installCompleted = false;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => EnrollmentEntryWorkflow.EnrollAsync(Code, CompanionInstallationPresence.Absent,
            _ => { installCompleted = true; stop.Cancel(); return Task.CompletedTask; },
            (_, _) => throw new Exception("must not enroll"), stop.Token));
        Assert.True(installCompleted);
    }
}
