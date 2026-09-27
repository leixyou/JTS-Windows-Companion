using System.Security.AccessControl;
using System.Security.Principal;

namespace JTS.WindowsCompanion.ReleaseManifestTool;

internal static class RestrictedKeyFile
{
    internal static FileStream CreateNew(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            using var identity = WindowsIdentity.GetCurrent();
            var owner = identity.User
                ?? throw new UnauthorizedAccessException("The current Windows identity has no SID.");
            var security = new FileSecurity();
            security.SetOwner(owner);
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl, AccessControlType.Allow));
            // The restrictive DACL is applied when the file is created, before
            // any private bytes exist; inherited directory ACLs never expose it.
            return new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.FullControl,
                FileShare.None, 4096, FileOptions.None, security);
        }

        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS() && !OperatingSystem.IsFreeBSD())
            throw new PlatformNotSupportedException("Owner-only key creation is unsupported on this platform.");
        return new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        });
    }

    internal static void AssertOwnerOnly(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            using var identity = WindowsIdentity.GetCurrent();
            var owner = identity.User
                ?? throw new UnauthorizedAccessException("The current Windows identity has no SID.");
            var security = new FileInfo(path).GetAccessControl();
            if (security.GetOwner(typeof(SecurityIdentifier))?.Equals(owner) != true)
                throw new UnauthorizedAccessException("The release key must be owned by the current user.");
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                if (rule.AccessControlType == AccessControlType.Allow && !rule.IdentityReference.Equals(owner))
                    throw new UnauthorizedAccessException("The release key grants access to another principal.");
            return;
        }

        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS() && !OperatingSystem.IsFreeBSD())
            throw new PlatformNotSupportedException("Owner-only key checks are unsupported on this platform.");
        var mode = File.GetUnixFileMode(path);
        const UnixFileMode sharedPermissions = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
        if ((mode & sharedPermissions) != 0)
            throw new UnauthorizedAccessException("The release key must not grant group or other permissions.");
    }
}
