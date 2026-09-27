using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace JTS.WindowsCompanion.UnattendedInstallation;

/// <summary>Enables only already-held privileges on a temporary thread token, never the process token.</summary>
[SupportedOSPlatform("windows")]
internal static class ProvisioningPrivileges
{
    internal static T Run<T>(Func<T> operation, params string[] names)
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (identity.IsSystem || identity.ImpersonationLevel != TokenImpersonationLevel.None
            || !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new UnattendedInstallationException("PROVISION_ELEVATED_INSTALLER_REQUIRED");
        ProvisioningNative.Require(ProvisioningNative.OpenProcessToken(ProvisioningNative.GetCurrentProcess(), 0xA, out var source));
        using (source)
        {
            using var elevation = ProvisioningToken.Read(source, 20);
            if (Marshal.ReadInt32(elevation.Pointer) == 0)
                throw new UnattendedInstallationException("PROVISION_ELEVATED_INSTALLER_REQUIRED");
            // Query + duplicate + impersonate + adjust privileges, SecurityImpersonation / TokenImpersonation.
            ProvisioningNative.Require(ProvisioningNative.DuplicateTokenEx(source, 0x2E, IntPtr.Zero, 2, 2, out var scoped));
            using (scoped)
            {
                foreach (var name in names)
                {
                    ProvisioningNative.Require(ProvisioningNative.LookupPrivilegeValue(null, name, out var luid));
                    var privilege = new ProvisioningNative.TokenPrivilege { Count = 1, Luid = luid, Attributes = 2 };
                    var success = ProvisioningNative.AdjustTokenPrivileges(scoped, false, ref privilege, 0, IntPtr.Zero, IntPtr.Zero);
                    if (!success || Marshal.GetLastPInvokeError() != 0)
                        throw new UnattendedInstallationException("PROVISION_INSTALLER_PRIVILEGE_REQUIRED");
                }
                // This callback is deliberately synchronous: the scoped impersonation never straddles an await.
                return WindowsIdentity.RunImpersonated(scoped, operation);
            }
        }
    }
}
