using Xunit;

namespace JTS.WindowsCompanion.UnattendedInstallation.Tests;

public sealed class LaunchContractTests
{
    [Fact]
    public void OnlyFixedImageAndPublicEnrollmentReachCommandLine()
    {
        using var f = new InstallationFixture(); var account = f.Account("authority");
        const string image = @"C:\Program Files\JTS Terminal\Companion25\JTS.WindowsCompanion.AuthorityProvisioner.exe";
        Assert.Equal('"' + image + "\" --provision " + f.Initial.EnrollmentId.ToString("D"), ProvisioningLaunchPlan.CommandLine(account, image));
        Assert.Throws<UnattendedInstallationException>(() => ProvisioningLaunchPlan.CommandLine(f.Account("worker"), image));
    }
    [Theory]
    [InlineData("powershell.exe")] [InlineData(@"C:\a\..\JTS.WindowsCompanion.AuthorityProvisioner.exe")]
    [InlineData(@"\\host\share\JTS.WindowsCompanion.AuthorityProvisioner.exe")]
    [InlineData(@"C:\JTS.WindowsCompanion.AuthorityProvisioner.exe:stream")]
    public void ArbitraryLaunchTargetsAreRejected(string path)
    {
        using var f = new InstallationFixture(); Assert.Throws<UnattendedInstallationException>(() => ProvisioningLaunchPlan.CommandLine(f.Account("authority"), path));
    }
    [Fact]
    public void EnvironmentDoesNotInheritInstallerSecretsOrRuntimeInjection()
    {
        var env = ProvisioningLaunchPlan.EnvironmentBlock(@"C:\Windows\System32", @"C:\Windows", @"C:\Users\fixture", @"C:\ProgramData", "fixture", "HOST");
        Assert.EndsWith("\0\0", env); Assert.Contains("PATH=C:\\Windows\\System32\0", env);
        Assert.Contains("DOTNET_EnableDiagnostics=0\0", env); Assert.DoesNotContain("STARTUP_HOOKS", env); Assert.DoesNotContain("COR_ENABLE_PROFILING", env);
        Assert.Throws<UnattendedInstallationException>(() => ProvisioningLaunchPlan.EnvironmentBlock(@"C:\Windows\System32", @"C:\Windows", @"C:\Users\fixture", @"C:\ProgramData", "user\0EVIL=yes", "HOST"));
    }
    [NonWindowsInstallerFact]
    public async Task NonWindowsEntryCannotInstallOrPrompt()
    {
        await Assert.ThrowsAsync<PlatformNotSupportedException>(() => WindowsUnattendedInstaller.InstallWithConsentAsync("unused", "https://relay.example.invalid/"));
    }
}

public sealed class NonWindowsInstallerFactAttribute : FactAttribute
{
    public NonWindowsInstallerFactAttribute()
    { if (OperatingSystem.IsWindows()) Skip = "Non-Windows refusal only; this fixture never invokes an actual installation."; }
}
