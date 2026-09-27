using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace JTS.WindowsCompanion.UnattendedInstallation;

[SupportedOSPlatform("windows")]
internal sealed class ProvisioningProfile(SafeAccessTokenHandle token)
{
    private IntPtr _profile;
    internal void Load(string account)
    {
        ProvisioningPrivileges.Run(() =>
        {
            var info = new ProvisioningNative.ProfileInfo
            { Size = (uint)Marshal.SizeOf<ProvisioningNative.ProfileInfo>(), Flags = 1, UserName = account };
            ProvisioningNative.Require(ProvisioningNative.LoadUserProfile(token, ref info), "PROVISION_PROFILE_LOAD_FAILED");
            _profile = info.Profile;
            ProvisioningNative.Require(_profile != IntPtr.Zero, "PROVISION_PROFILE_LOAD_FAILED");
            return true;
        }, "SeBackupPrivilege", "SeRestorePrivilege");
    }

    internal string Directory()
    {
        var size = 241u; var value = new StringBuilder((int)size);
        ProvisioningNative.Require(ProvisioningNative.GetUserProfileDirectory(token, value, ref size), "PROVISION_PROFILE_PATH_REJECTED");
        return value.ToString();
    }

    internal void UnloadAfterConfirmedStop()
    {
        if (_profile == IntPtr.Zero) return;
        ProvisioningPrivileges.Run(() =>
        {
            ProvisioningNative.Require(ProvisioningNative.UnloadUserProfile(token, _profile), "PROVISION_PROFILE_UNLOAD_UNCONFIRMED");
            _profile = IntPtr.Zero;
            return true;
        }, "SeBackupPrivilege", "SeRestorePrivilege");
    }
}
