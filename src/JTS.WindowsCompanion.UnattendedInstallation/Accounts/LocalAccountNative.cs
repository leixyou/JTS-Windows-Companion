using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace JTS.WindowsCompanion.UnattendedInstallation;

[SupportedOSPlatform("windows")]
internal static class LocalAccountNative
{
    internal const uint Disabled = 0x2, UserNotFound = 2221, UserExists = 2224;
    internal const uint RequiredFlags = 0x1 | 0x40 | 0x200 | 0x10000 | 0x100000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct UserInfo1
    {
        [MarshalAs(UnmanagedType.LPWStr)] internal string Name;
        internal IntPtr Password;
        internal uint PasswordAge, Privilege;
        internal IntPtr HomeDirectory;
        [MarshalAs(UnmanagedType.LPWStr)] internal string Comment;
        internal uint Flags;
        internal IntPtr ScriptPath;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct UserInfo23
    { internal IntPtr Name, FullName, Comment; internal uint Flags; internal IntPtr Sid; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct UserModals2 { internal IntPtr DomainName, DomainSid; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct LsaObjectAttributes
    {
        internal uint Length; internal IntPtr RootDirectory, ObjectName;
        internal uint Attributes; internal IntPtr SecurityDescriptor, SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct LsaString { internal ushort Length, MaximumLength; internal IntPtr Buffer; }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    internal static extern uint NetUserAdd(string? serverName, uint level, ref UserInfo1 info, out uint parameterError);
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    internal static extern uint NetUserGetInfo(string? serverName, string name, uint level, out IntPtr buffer);
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    internal static extern uint NetUserSetInfo(string? serverName, string name, uint level, ref uint flags, out uint parameterError);
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    internal static extern uint NetUserDel(string? serverName, string name);
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    internal static extern uint NetUserModalsGet(string? serverName, uint level, out IntPtr buffer);
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    internal static extern uint NetUserGetLocalGroups(string? serverName, string name, uint level, uint flags,
        out IntPtr buffer, uint preferredMaximumLength, out uint entriesRead, out uint totalEntries);
    [DllImport("netapi32.dll")]
    internal static extern uint NetApiBufferFree(IntPtr buffer);
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    internal static extern uint DsRoleGetPrimaryDomainInformation(string? serverName, int level, out IntPtr buffer);
    [DllImport("netapi32.dll")]
    internal static extern void DsRoleFreeMemory(IntPtr buffer);
    [DllImport("advapi32.dll")]
    internal static extern uint LsaOpenPolicy(IntPtr systemName, ref LsaObjectAttributes attributes, uint access, out IntPtr handle);
    [DllImport("advapi32.dll")]
    internal static extern uint LsaAddAccountRights(IntPtr handle, byte[] sid, [In] LsaString[] rights, uint count);
    [DllImport("advapi32.dll")]
    internal static extern uint LsaEnumerateAccountRights(IntPtr handle, byte[] sid, out IntPtr rights, out uint count);
    [DllImport("advapi32.dll")]
    internal static extern uint LsaRemoveAccountRights(IntPtr handle, byte[] sid, [MarshalAs(UnmanagedType.U1)] bool allRights,
        IntPtr rights, uint count);
    [DllImport("advapi32.dll")]
    internal static extern uint LsaFreeMemory(IntPtr buffer);
    [DllImport("advapi32.dll")]
    internal static extern uint LsaClose(IntPtr handle);
}
