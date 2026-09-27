using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace JTS.WindowsCompanion.UnattendedInstallation;

/// <summary>A fresh noninteractive station. Never opens or edits WinSta0 / the signed-in user's desktop.</summary>
[SupportedOSPlatform("windows")]
internal sealed class ProvisioningDesktop : IDisposable
{
    private static readonly object StationGate = new();
    private IntPtr _station, _desktop;
    internal string Name { get; }

    internal ProvisioningDesktop(string accountSid)
    {
        var stationName = "JTS.Provision." + Guid.NewGuid().ToString("N");
        Name = stationName + "\\Authority";
        ProvisioningNative.Require(ProvisioningNative.ConvertSecurityDescriptor(
            "O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + accountSid + ")", 1, out var descriptor, IntPtr.Zero));
        try
        {
            var attributes = new ProvisioningNative.SecurityAttributes
            { Size = (uint)Marshal.SizeOf<ProvisioningNative.SecurityAttributes>(), Descriptor = descriptor, Inherit = false };
            // SetProcessWindowStation is process-wide. No await, message pump, callbacks or process creation
            // occurs while it is temporarily changed. The installer must keep other UI creation quiescent.
            lock (StationGate)
            {
                var original = ProvisioningNative.GetProcessWindowStation();
                ProvisioningNative.Require(original != IntPtr.Zero);
                // CWF_CREATE_ONLY prevents even an improbable name collision from adopting an existing station.
                _station = ProvisioningNative.CreateWindowStation(stationName, 1, 0xF037F, ref attributes);
                ProvisioningNative.Require(_station != IntPtr.Zero, "PROVISION_DESKTOP_CREATE_FAILED");
                ProvisioningNative.Require(ProvisioningNative.GetUserObjectInformation(_station, 1, out var flags,
                    (uint)Marshal.SizeOf<ProvisioningNative.UserObjectFlags>(), out _));
                ProvisioningNative.Require((flags.Flags & 1) == 0 && !flags.Inherit, "PROVISION_DESKTOP_NOT_ISOLATED");
                ProvisioningNative.Require(ProvisioningNative.SetProcessWindowStation(_station));
                try
                {
                    _desktop = ProvisioningNative.CreateDesktop("Authority", IntPtr.Zero, IntPtr.Zero, 0, 0xF01FF, ref attributes);
                    ProvisioningNative.Require(_desktop != IntPtr.Zero, "PROVISION_DESKTOP_CREATE_FAILED");
                }
                finally
                {
                    ProvisioningNative.Require(ProvisioningNative.SetProcessWindowStation(original), "PROVISION_DESKTOP_RESTORE_FAILED");
                }
            }
        }
        catch { Dispose(); throw; }
        finally { ProvisioningNative.LocalFree(descriptor); }
    }

    public void Dispose()
    {
        if (_desktop != IntPtr.Zero) { ProvisioningNative.CloseDesktop(_desktop); _desktop = IntPtr.Zero; }
        if (_station != IntPtr.Zero) { ProvisioningNative.CloseWindowStation(_station); _station = IntPtr.Zero; }
    }
}
