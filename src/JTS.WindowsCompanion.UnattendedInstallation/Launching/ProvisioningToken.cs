using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace JTS.WindowsCompanion.UnattendedInstallation;

[SupportedOSPlatform("windows")]
internal static class ProvisioningToken
{
    private static readonly HashSet<string> PrivilegedGroups = new(StringComparer.Ordinal)
    { "S-1-5-32-544", "S-1-5-32-547", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551" };

    internal static SafeAccessTokenHandle Restricted(SafeAccessTokenHandle raw, string sid)
    {
        Verify(raw, sid, normalized: false);
        using var privileges = Read(raw, 3);
        var count = Marshal.ReadInt32(privileges.Pointer);
        if (count is < 0 or > 256 || 4L + count * 12L > privileges.Length) Fail();
        using var removed = new NativeBuffer(Math.Max(12, count * 12));
        var removedCount = 0;
        for (var i = 0; i < count; i++)
        {
            var source = privileges.Pointer + 4 + 12 * i;
            if (PrivilegeName(source) == "SeChangeNotifyPrivilege") continue;
            // Explicitly DELETE unwanted privileges. Disabling a privilege leaves it present and is insufficient.
            Marshal.StructureToPtr(Marshal.PtrToStructure<ProvisioningNative.Luid>(source), removed.Pointer + 12 * removedCount, false);
            Marshal.WriteInt32(removed.Pointer + 12 * removedCount + 8, 0); removedCount++;
        }
        ProvisioningNative.Require(ProvisioningNative.CreateRestrictedToken(raw, 0, 0, IntPtr.Zero,
            (uint)removedCount, removed.Pointer, 0, IntPtr.Zero, out var result), "PROVISION_TOKEN_RESTRICTION_FAILED");
        try
        {
            var medium = new SecurityIdentifier("S-1-16-8192");
            var bytes = new byte[medium.BinaryLength]; medium.GetBinaryForm(bytes, 0);
            using var integrity = new NativeBuffer(bytes.Length); Marshal.Copy(bytes, 0, integrity.Pointer, bytes.Length);
            var label = new ProvisioningNative.SidAndAttributes { Sid = integrity.Pointer, Attributes = 0x20 };
            ProvisioningNative.Require(ProvisioningNative.SetTokenInformation(result, 25, ref label,
                Marshal.SizeOf<ProvisioningNative.SidAndAttributes>() + bytes.Length), "PROVISION_TOKEN_RESTRICTION_FAILED");
            Verify(result, sid, normalized: true);
            return result;
        }
        catch { result.Dispose(); throw; }
    }

    internal static void VerifyProcess(SafeFileHandle process, string sid)
    {
        ProvisioningNative.Require(ProvisioningNative.OpenProcessToken(process.DangerousGetHandle(), 8, out var token));
        using (token) Verify(token, sid, normalized: true);
    }

    private static void Verify(SafeAccessTokenHandle token, string sid, bool normalized)
    {
        using var user = Read(token, 1); using var groups = Read(token, 2);
        using var elevation = Read(token, 20); using var type = Read(token, 8);
        using var integrity = Read(token, 25); using var privileges = Read(token, 3);
        var actual = new SecurityIdentifier(Marshal.ReadIntPtr(user.Pointer)).Value;
        var integritySid = new SecurityIdentifier(Marshal.ReadIntPtr(integrity.Pointer)).Value;
        if (actual != sid || Marshal.ReadInt32(elevation.Pointer) != 0 || Marshal.ReadInt32(type.Pointer) != 1
            || !int.TryParse(integritySid.Split('-')[^1], NumberStyles.None, CultureInfo.InvariantCulture, out var rid)
            || (normalized && rid != 8192)) Fail();
        var count = Marshal.ReadInt32(groups.Pointer);
        if (count is < 0 or > 4096 || 8L + count * 16L > groups.Length) Fail();
        for (var i = 0; i < count; i++)
            if (PrivilegedGroups.Contains(new SecurityIdentifier(Marshal.ReadIntPtr(groups.Pointer, 8 + 16 * i)).Value)) Fail();
        var privilegeCount = Marshal.ReadInt32(privileges.Pointer);
        if (privilegeCount is < 0 or > 256 || 4L + privilegeCount * 12L > privileges.Length) Fail();
        if (normalized)
            for (var i = 0; i < privilegeCount; i++)
                if (PrivilegeName(privileges.Pointer + 4 + 12 * i) != "SeChangeNotifyPrivilege") Fail();
    }

    private static string PrivilegeName(IntPtr pointer)
    {
        var luid = Marshal.PtrToStructure<ProvisioningNative.Luid>(pointer); var size = 0;
        ProvisioningNative.LookupPrivilegeName(null, ref luid, null, ref size);
        if (size is < 1 or > 256) Fail();
        var name = new StringBuilder(size + 1); size++;
        ProvisioningNative.Require(ProvisioningNative.LookupPrivilegeName(null, ref luid, name, ref size));
        return name.ToString();
    }

    internal static NativeBuffer Read(SafeAccessTokenHandle token, int infoClass)
    {
        ProvisioningNative.GetTokenInformation(token, infoClass, IntPtr.Zero, 0, out var length);
        if (length is < 4 or > 1_048_576) Fail();
        var buffer = new NativeBuffer(length);
        try { ProvisioningNative.Require(ProvisioningNative.GetTokenInformation(token, infoClass, buffer.Pointer, length, out _)); return buffer; }
        catch { buffer.Dispose(); throw; }
    }
    private static void Fail() => throw new UnattendedInstallationException("PROVISION_TOKEN_REJECTED");
}

internal sealed class NativeBuffer(int length) : IDisposable
{
    internal IntPtr Pointer { get; private set; } = Marshal.AllocHGlobal(length);
    internal int Length { get; } = length;
    public void Dispose() { if (Pointer != IntPtr.Zero) { Marshal.FreeHGlobal(Pointer); Pointer = IntPtr.Zero; } }
}
