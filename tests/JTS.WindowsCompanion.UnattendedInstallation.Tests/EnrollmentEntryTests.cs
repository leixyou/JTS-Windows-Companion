using JTS.WindowsCompanion.UnattendedSetup;
using Xunit;

namespace JTS.WindowsCompanion.UnattendedInstallation.Tests;

public sealed class EnrollmentEntryTests
{
    [Fact]
    public void DefaultAndManageOpenTheSameConnectionManager()
    {
        Assert.Equal(SetupEntryMode.Interactive, SetupEntryArguments.Parse([]));
        Assert.Equal(SetupEntryMode.Manage, SetupEntryArguments.Parse(["--manage"]));
        Assert.Equal(SetupEntryMode.Status, SetupEntryArguments.Parse(["--status"]));
        Assert.Equal(SetupEntryMode.EnrollStandardInput, SetupEntryArguments.Parse(["--enroll-code"]));
    }

    [Theory]
    [InlineData("--enroll-code", "jts-pair://secret")]
    [InlineData("--code-file", "secret.txt")]
    [InlineData("--manage", "--status")]
    [InlineData("--status", "--status")]
    [InlineData("--unknown", "value")]
    public void CodeAndUnknownOptionsNeverEnterAnArgumentBasedSecretPath(string first, string second)
    {
        var error = Assert.Throws<ArgumentException>(() => SetupEntryArguments.Parse([first, second]));
        Assert.Equal("SETUP_ARGUMENTS_REJECTED", error.Message);
        Assert.DoesNotContain(second, error.Message);
    }

    [Fact]
    public void LegacyExplicitDelegatedInstallationStillHasItsOwnEntryPoint()
        => Assert.Equal(SetupEntryMode.DelegatedInstallation, SetupEntryArguments.Parse([
            "--relay", "https://relay.example", "--delegated-enrollment", "request.json", "--sha256", "hash", "--export", "public.json"]));

    [Fact]
    public async Task StandardInputConsumesOneLineWithoutWaitingForEndOfStream()
    {
        using var input = new StringReader("  jts-pair://enroll?code=test  \r\nDO NOT READ THIS LINE");
        Assert.Equal("jts-pair://enroll?code=test", await EnrollmentCodeInput.ReadAsync(input, default));
        Assert.Equal("DO NOT READ THIS LINE", await input.ReadToEndAsync());
    }

    [Theory]
    [InlineData("")]
    [InlineData("  \r\n")]
    [InlineData("secret\0data")]
    public async Task InvalidInputDoesNotAppearInFailureOutput(string text)
    {
        var error = await Assert.ThrowsAsync<ArgumentException>(() => EnrollmentCodeInput.ReadAsync(new StringReader(text), default));
        Assert.Equal("ENROLLMENT_CODE_INVALID", error.Message);
    }

    [Fact]
    public async Task StandardInputIsBoundedAtTheCodeContractLimit()
    {
        Assert.Equal(4096, (await EnrollmentCodeInput.ReadAsync(new StringReader(new string('a', 4096)), default)).Length);
        var error = await Assert.ThrowsAsync<ArgumentException>(() => EnrollmentCodeInput.ReadAsync(new StringReader(new string('b', 4097)), default));
        Assert.Equal("ENROLLMENT_CODE_INVALID", error.Message);
    }

    [Fact]
    public async Task CancelledInputDoesNotInstallOrWaitForAnotherLine()
    {
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => EnrollmentCodeInput.ReadAsync(new StringReader("code"), cancel.Token));
    }

    [Theory]
    [InlineData(false, false, false, CompanionInstallationPresence.Absent)]
    [InlineData(true, true, false, CompanionInstallationPresence.Installed)]
    [InlineData(true, true, true, CompanionInstallationPresence.Installed)]
    [InlineData(true, false, false, CompanionInstallationPresence.NeedsReview)]
    [InlineData(false, true, false, CompanionInstallationPresence.NeedsReview)]
    [InlineData(false, false, true, CompanionInstallationPresence.NeedsReview)]
    public void ExistingOrPartialInstallNeverBecomesAFirstInstall(bool service, bool state, bool journal, CompanionInstallationPresence expected)
        => Assert.Equal(expected, WindowsInstallationPresence.Evaluate(service, state, journal));

    [Fact]
    public void BoundCredentialsStayBoundUntilExplicitRevocationIndependentOfRdp()
    {
        var bound = EnrollmentPresentation.From("bound", true);
        Assert.False(bound.MaySubmit); Assert.True(bound.MayRevoke);
        Assert.Contains("until you revoke", bound.Detail);
        Assert.Contains("RDP login: not checked", EnrollmentPresentation.RdpStatus);
        Assert.Contains("does not consume an unbound, unexpired code", EnrollmentPresentation.RdpStatus);
        Assert.Contains("or revoke a bound device", EnrollmentPresentation.RdpStatus);
    }

    [Theory]
    [InlineData("idle", true, false)]
    [InlineData("pending", false, true)]
    [InlineData("claimed", false, true)]
    [InlineData("committing", false, true)]
    [InlineData("revoking", false, false)]
    [InlineData("revoked", true, false)]
    [InlineData("expired", true, false)]
    [InlineData("cancelled", true, false)]
    [InlineData("unknown", false, true)]
    public void PendingAttemptCannotBeReplacedButCanBeRevoked(string state, bool submit, bool revoke)
    {
        var view = EnrollmentPresentation.From(state, true);
        Assert.Equal(submit, view.MaySubmit); Assert.Equal(revoke, view.MayRevoke);
    }

    [Fact]
    public void UnexpectedEnrollmentErrorNeverLeaksTheCode()
        => Assert.DoesNotContain("private-code", EnrollmentFailure.FromCode("private-code"));
}
