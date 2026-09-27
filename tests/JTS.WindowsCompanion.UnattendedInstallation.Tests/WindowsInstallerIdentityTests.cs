using System.Security.Principal;
using Xunit;

namespace JTS.WindowsCompanion.UnattendedInstallation.Tests;

public sealed class WindowsInstallerIdentityTests
{
    [WindowsInstallerIdentityFact]
    public void InstallerTokenCanCheckEffectiveAdministratorMembership()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        using var expected = WindowsIdentity.GetCurrent();
        using var actual = WindowsUnattendedInstaller.OpenIdentityForMembershipChecks();
        Assert.Equal(expected.User?.Value, actual.User?.Value);
        Assert.Equal(new WindowsPrincipal(expected).IsInRole(WindowsBuiltInRole.Administrator),
            new WindowsPrincipal(actual).IsInRole(WindowsBuiltInRole.Administrator));
    }
}

internal sealed class WindowsInstallerIdentityFactAttribute : FactAttribute
{
    public WindowsInstallerIdentityFactAttribute()
    {
        if (!OperatingSystem.IsWindows()) Skip = "Requires an actual Windows token; does not install or change any account.";
    }
}
