using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace JTS.WindowsCompanion.UnattendedInstallation;

[SupportedOSPlatform("windows")]
internal static class InstalledServiceInspection
{
    internal static InstallationScmNative.Status State(InstallationServiceHandle service)
    {
        InstallationScmNative.Require(InstallationScmNative.QueryServiceStatusEx(service, 0, out var state,
            Marshal.SizeOf<InstallationScmNative.Status>(), out _));
        if (state.Type != 0x10 || state.Flags != 0) throw Rejected();
        return state;
    }
    internal static void RequireStoppedDisabled(InstallationServiceHandle service)
    {
        var state = State(service);
        using var configuration = Query(service, 0);
        var config = configuration.Read<InstallationScmNative.Configuration>();
        if (state.State != 1 || state.Pid != 0 || config.Type != 0x10 || config.StartType != 4)
            throw new UnattendedInstallationException("INSTALL_SERVICE_ROLLBACK_UNSAFE");
    }
    internal static void Validate(InstallationServiceHandle service, InstalledServiceDefinition expected, uint start)
    {
        using var configuration = Query(service, 0);
        var config = configuration.Read<InstallationScmNative.Configuration>();
        if (config.Type != 0x10 || config.StartType != start || config.ErrorControl != 1 || config.Tag != 0
            || !string.Equals(configuration.String(config.BinaryPath), expected.Command, StringComparison.Ordinal)
            || !string.Equals(configuration.String(config.Account), expected.AccountName, StringComparison.OrdinalIgnoreCase)
            || configuration.String(config.DisplayName) != expected.DisplayName
            || configuration.String(config.LoadGroup).Length != 0 || configuration.MultiString(config.Dependencies).Length != 0)
            throw Rejected();
        var sid = ((SecurityIdentifier)new NTAccount(Environment.MachineName, expected.AccountName[2..]).Translate(typeof(SecurityIdentifier))).Value;
        if (sid != expected.AccountSid) throw Rejected();
        using var description = Query(service, 1);
        if (description.String(description.Read<IntPtr>()) != expected.Description) throw Rejected();
        using var privileges = Query(service, 6);
        if (privileges.MultiString(privileges.Read<IntPtr>()) is not ["SeChangeNotifyPrivilege"]) throw Rejected();
        using var recovery = Query(service, 2);
        var actions = recovery.Read<InstallationScmNative.FailureActions>();
        if (actions.Count != 0 || recovery.String(actions.Reboot).Length != 0 || recovery.String(actions.Command).Length != 0)
            throw Rejected();
        foreach (var setting in new[] { (3, 0u), (4, 0u), (5, 1u), (8, 0u), (12, 0u) })
        {
            using var data = Query(service, setting.Item1);
            if (data.Read<uint>() != setting.Item2) throw Rejected();
        }
        using var security = Query(service, -1);
        ValidateSecurity(security, expected.ControllerSid);
    }

    private static void ValidateSecurity(InstallationScmBuffer buffer, string? controller)
    {
        var bytes = new byte[buffer.Length]; Marshal.Copy(buffer.Pointer, bytes, 0, bytes.Length);
        var descriptor = new RawSecurityDescriptor(bytes, 0);
        if (descriptor.Owner?.Value != "S-1-5-32-544" || descriptor.DiscretionaryAcl is null
            || (descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0) throw Rejected();
        var expected = new Dictionary<string, int>(StringComparer.Ordinal)
        { ["S-1-5-18"] = (int)InstallationScmNative.AllAccess, ["S-1-5-32-544"] = (int)InstallationScmNative.AllAccess };
        if (controller is not null) expected.Add(controller, 0x00020035);
        foreach (var entry in descriptor.DiscretionaryAcl)
        {
            if (entry is not CommonAce ace || ace.IsCallback || ace.AceQualifier != AceQualifier.AccessAllowed
                || ace.AceFlags != AceFlags.None || !expected.Remove(ace.SecurityIdentifier.Value, out var rights)
                || ace.AccessMask != rights) throw Rejected();
        }
        if (expected.Count != 0) throw Rejected();
    }

    private static InstallationScmBuffer Query(InstallationServiceHandle service, int kind)
    {
        var needed = 0;
        bool Call(IntPtr pointer, int length) => kind switch
        {
            0 => InstallationScmNative.QueryConfiguration(service, pointer, length, out needed),
            -1 => InstallationScmNative.QueryServiceObjectSecurity(service, 5, pointer, length, out needed),
            _ => InstallationScmNative.QueryOptional(service, kind, pointer, length, out needed),
        };
        _ = Call(IntPtr.Zero, 0);
        if (Marshal.GetLastWin32Error() != 122 || needed is < 4 or > 8192) throw Rejected();
        var buffer = new InstallationScmBuffer(needed);
        try { InstallationScmNative.Require(Call(buffer.Pointer, buffer.Length)); return buffer; }
        catch { buffer.Dispose(); throw; }
    }
    private static UnattendedInstallationException Rejected() => new("INSTALL_SERVICE_CONFIGURATION_REJECTED");
}
