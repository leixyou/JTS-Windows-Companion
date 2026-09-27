using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace JTS.WindowsCompanion.UnattendedInstallation;

[SupportedOSPlatform("windows")]
internal static class InstalledServiceSettings
{
    internal static void Configure(InstallationServiceHandle service, InstalledServiceDefinition definition)
    {
        WriteString(service, 1, definition.Description);
        WriteString(service, 6, "SeChangeNotifyPrivilege\0"); // Allocator adds final multi-string terminator.
        Write(service, 5, 1u); // SERVICE_SID_TYPE_UNRESTRICTED, never a built-in service account.
        Write(service, 3, 0u); Write(service, 4, 0u); Write(service, 12, 0u);
        using var empty = new InstallationScmBuffer(8);
        Marshal.WriteInt64(empty.Pointer, 0);
        // A non-null zero-element action array explicitly clears actions; null means unchanged.
        Write(service, 2, new InstallationScmNative.FailureActions
        { Reboot = empty.Pointer, Command = empty.Pointer, Actions = empty.Pointer });
        // New services have no triggers. Removing an already-empty list returns INVALID_PARAMETER;
        // inspect it instead of suppressing that error or altering an unrelated registration.
        Protect(service, definition.ControllerSid);
    }

    internal static void SetStartType(InstallationServiceHandle service, uint start)
    {
        if (start is not (2 or 3)) throw new UnattendedInstallationException("INSTALL_SERVICE_START_TYPE_REJECTED");
        InstallationScmNative.Require(InstallationScmNative.ChangeConfiguration(service, uint.MaxValue, start, uint.MaxValue,
            null, null, IntPtr.Zero, null, null, IntPtr.Zero, null));
    }

    private static void WriteString(InstallationServiceHandle service, int kind, string text)
    {
        var pointer = Marshal.StringToHGlobalUni(text);
        try { Write(service, kind, pointer); }
        finally { Marshal.FreeHGlobal(pointer); }
    }
    private static void Write<T>(InstallationServiceHandle service, int kind, T value) where T : struct
    {
        using var buffer = new InstallationScmBuffer(Marshal.SizeOf<T>());
        Marshal.StructureToPtr(value, buffer.Pointer, false);
        InstallationScmNative.Require(InstallationScmNative.ChangeOptional(service, kind, buffer.Pointer));
    }

    private static void Protect(InstallationServiceHandle service, string? controller)
    {
        var owner = new SecurityIdentifier("S-1-5-32-544");
        var acl = new RawAcl(2, controller is null ? 2 : 3);
        void Allow(string sid, int mask) => acl.InsertAce(acl.Count,
            new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, mask, new SecurityIdentifier(sid), false, null));
        Allow("S-1-5-18", (int)InstallationScmNative.AllAccess);
        Allow(owner.Value, (int)InstallationScmNative.AllAccess);
        if (controller is not null) Allow(controller, 0x00020035);
        var ownerBytes = new byte[owner.BinaryLength]; owner.GetBinaryForm(ownerBytes, 0);
        var aclBytes = new byte[acl.BinaryLength]; acl.GetBinaryForm(aclBytes, 0);
        using var nativeOwner = new InstallationScmBuffer(ownerBytes.Length);
        using var nativeAcl = new InstallationScmBuffer(aclBytes.Length);
        Marshal.Copy(ownerBytes, 0, nativeOwner.Pointer, ownerBytes.Length);
        Marshal.Copy(aclBytes, 0, nativeAcl.Pointer, aclBytes.Length);
        // Handle-based SE_SERVICE assignment, including PROTECTED_DACL_SECURITY_INFORMATION.
        // SetServiceObjectSecurity silently ignores unsupported flags, so do not use it for protection.
        InstallationScmNative.Require(InstallationScmNative.SetSecurityInfo(service, 2, 0x80000005,
            nativeOwner.Pointer, IntPtr.Zero, nativeAcl.Pointer, IntPtr.Zero) == 0, "INSTALL_SERVICE_ACL_FAILED");
    }
}
