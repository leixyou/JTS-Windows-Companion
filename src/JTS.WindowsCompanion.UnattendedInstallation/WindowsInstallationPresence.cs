using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace JTS.WindowsCompanion.UnattendedInstallation;

public enum CompanionInstallationPresence { Absent, Installed, NeedsReview }

public static class WindowsInstallationPresence
{
    public static CompanionInstallationPresence Inspect()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("UNATTENDED_INSTALL_WINDOWS_REQUIRED");
        return InspectWindows();
    }
    [SupportedOSPlatform("windows")]
    private static CompanionInstallationPresence InspectWindows()
    {
        using var manager = InstallationScmNative.OpenManager(null, null, 1);
        InstallationScmNative.Require(!manager.IsInvalid, "INSTALL_SERVICE_INSPECTION_UNAVAILABLE");
        using var service = InstallationScmNative.OpenService(manager, "JTSCompanionAuthority25", 4);
        var exists = !service.IsInvalid;
        if (!exists && Marshal.GetLastWin32Error() != 1060)
            throw new UnattendedInstallationException("INSTALL_SERVICE_INSPECTION_UNAVAILABLE");
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "JTS Terminal", "Companion25");
        return Evaluate(exists, Directory.Exists(Path.Combine(root, "authority")), File.Exists(Path.Combine(root, ".install", "transaction.json")));
    }
    internal static CompanionInstallationPresence Evaluate(bool serviceExists, bool stateExists, bool journalExists)
        => serviceExists && stateExists ? CompanionInstallationPresence.Installed
            : serviceExists || stateExists || journalExists ? CompanionInstallationPresence.NeedsReview : CompanionInstallationPresence.Absent;
}
