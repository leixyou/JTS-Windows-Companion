using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;

namespace JTS.WindowsCompanion.UnattendedInstallation;

[SupportedOSPlatform("windows")]
internal static class WindowsExclusiveDirectory
{
    internal static void Create(string path, string sddl)
    {
        var descriptor = new RawSecurityDescriptor(sddl); var bytes = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(bytes, 0);
        var pointer = Marshal.AllocHGlobal(bytes.Length);
        try
        {
            Marshal.Copy(bytes, 0, pointer, bytes.Length);
            var attributes = new Attributes { Length = Marshal.SizeOf<Attributes>(), Descriptor = pointer };
            // Unlike DirectoryInfo.Create, native creation never claims a pre-existing directory as ours.
            if (!CreateDirectory(path, ref attributes)) throw new UnattendedInstallationException("INSTALL_EXCLUSIVE_DIRECTORY_CREATION_FAILED");
        }
        finally { Marshal.FreeHGlobal(pointer); }
    }
    [StructLayout(LayoutKind.Sequential)] private struct Attributes
    { internal int Length; internal IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] internal bool Inherit; }
    [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CreateDirectory(string path, ref Attributes attributes);
}
