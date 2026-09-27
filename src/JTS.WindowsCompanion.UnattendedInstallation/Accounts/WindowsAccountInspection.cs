using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace JTS.WindowsCompanion.UnattendedInstallation;

internal sealed record LocalAccountSnapshot(string Name, string Sid, string Marker, uint Flags);

[SupportedOSPlatform("windows")]
internal static class WindowsAccountInspection
{
    internal static void RequireInstaller()
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10) || !Environment.Is64BitProcess)
            throw new UnattendedInstallationException("INSTALL_WINDOWS_REQUIRED");
        using var current = WindowsIdentity.GetCurrent();
        if (current.ImpersonationLevel != TokenImpersonationLevel.None
            || !new WindowsPrincipal(current).IsInRole(WindowsBuiltInRole.Administrator))
            throw new UnattendedInstallationException("INSTALL_ELEVATION_REQUIRED");
        var status = LocalAccountNative.DsRoleGetPrimaryDomainInformation(null, 1, out var buffer);
        try
        {
            // NetUser APIs on a domain controller mutate domain users, not local SAM accounts.
            if (status != 0 || buffer == IntPtr.Zero || Marshal.ReadInt32(buffer) is < 0 or > 3)
                throw new UnattendedInstallationException("INSTALL_LOCAL_SAM_REQUIRED");
        }
        finally { if (buffer != IntPtr.Zero) LocalAccountNative.DsRoleFreeMemory(buffer); }
    }

    internal static LocalAccountSnapshot? Read(string name)
    {
        var status = LocalAccountNative.NetUserGetInfo(null, name, 23, out var buffer);
        try
        {
            if (status == LocalAccountNative.UserNotFound) return null;
            if (status != 0 || buffer == IntPtr.Zero) throw new UnattendedInstallationException("INSTALL_ACCOUNT_QUERY_FAILED");
            var account = Marshal.PtrToStructure<LocalAccountNative.UserInfo23>(buffer);
            if (account.Sid == IntPtr.Zero) throw new UnattendedInstallationException("INSTALL_ACCOUNT_QUERY_FAILED");
            var sid = new SecurityIdentifier(account.Sid);
            RequireLocalSid(sid);
            return new LocalAccountSnapshot(ReadString(account.Name, 20), sid.Value, ReadString(account.Comment, 128), account.Flags);
        }
        catch (ArgumentException) { throw new UnattendedInstallationException("INSTALL_ACCOUNT_QUERY_FAILED"); }
        finally { if (buffer != IntPtr.Zero) _ = LocalAccountNative.NetApiBufferFree(buffer); }
    }

    internal static void RequireOrdinaryGroups(string name)
    {
        var status = LocalAccountNative.NetUserGetLocalGroups(null, name, 0, 1, out var buffer, 16384, out var count, out var total);
        try
        {
            if (status != 0 || count != total || count > 32 || (count != 0 && buffer == IntPtr.Zero))
                throw new UnattendedInstallationException("INSTALL_ACCOUNT_GROUPS_REJECTED");
            for (var i = 0; i < count; i++)
            {
                var group = ReadString(Marshal.ReadIntPtr(buffer, checked((int)i * IntPtr.Size)), 256);
                var sid = (SecurityIdentifier)new NTAccount(Environment.MachineName, group).Translate(typeof(SecurityIdentifier));
                // Never add to or accept Administrators, Power Users, operators, or a custom group.
                if (sid.Value != "S-1-5-32-545") throw new UnattendedInstallationException("INSTALL_ACCOUNT_GROUPS_REJECTED");
            }
        }
        catch (IdentityNotMappedException) { throw new UnattendedInstallationException("INSTALL_ACCOUNT_GROUPS_REJECTED"); }
        finally { if (buffer != IntPtr.Zero) _ = LocalAccountNative.NetApiBufferFree(buffer); }
    }

    private static void RequireLocalSid(SecurityIdentifier sid)
    {
        var status = LocalAccountNative.NetUserModalsGet(null, 2, out var buffer);
        try
        {
            if (status != 0 || buffer == IntPtr.Zero) throw new UnattendedInstallationException("INSTALL_LOCAL_SAM_REQUIRED");
            var domain = Marshal.PtrToStructure<LocalAccountNative.UserModals2>(buffer);
            if (domain.DomainSid == IntPtr.Zero || sid.AccountDomainSid is not { } accountDomain
                || accountDomain != new SecurityIdentifier(domain.DomainSid))
                throw new UnattendedInstallationException("INSTALL_ACCOUNT_SID_REJECTED");
        }
        finally { if (buffer != IntPtr.Zero) _ = LocalAccountNative.NetApiBufferFree(buffer); }
    }

    private static string ReadString(IntPtr pointer, int maximum)
    {
        if (pointer == IntPtr.Zero) return "";
        var length = 0;
        while (length <= maximum && Marshal.ReadInt16(pointer, length * sizeof(char)) != 0) length++;
        if (length > maximum) throw new UnattendedInstallationException("INSTALL_ACCOUNT_QUERY_FAILED");
        return Marshal.PtrToStringUni(pointer, length) ?? throw new UnattendedInstallationException("INSTALL_ACCOUNT_QUERY_FAILED");
    }
}
