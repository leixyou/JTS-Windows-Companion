using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace JTS.WindowsCompanion.UnattendedInstallation;

internal static partial class ProvisioningNative
{
    [DllImport("userenv.dll", EntryPoint = "LoadUserProfileW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool LoadUserProfile(SafeAccessTokenHandle token, ref ProfileInfo profile);
    [DllImport("userenv.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool UnloadUserProfile(SafeAccessTokenHandle token, IntPtr profile);
    [DllImport("userenv.dll", EntryPoint = "GetUserProfileDirectoryW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool GetUserProfileDirectory(SafeAccessTokenHandle token, StringBuilder path, ref uint size);
    [DllImport("advapi32.dll", EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool ConvertSecurityDescriptor(string sddl, uint revision, out IntPtr descriptor, IntPtr size);
    [DllImport("kernel32.dll")] internal static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("user32.dll", EntryPoint = "CreateWindowStationW", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern IntPtr CreateWindowStation(string name, uint flags, uint access, ref SecurityAttributes attributes);
    [DllImport("user32.dll", SetLastError = true)] internal static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool SetProcessWindowStation(IntPtr station);
    [DllImport("user32.dll", EntryPoint = "CreateDesktopW", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern IntPtr CreateDesktop(string name, IntPtr device, IntPtr mode, uint flags, uint access, ref SecurityAttributes attributes);
    [DllImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool CloseDesktop(IntPtr desktop);
    [DllImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool CloseWindowStation(IntPtr station);
    [DllImport("user32.dll", EntryPoint = "GetUserObjectInformationW", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetUserObjectInformation(IntPtr handle, int index, out UserObjectFlags flags, uint size, out uint returned);
}
