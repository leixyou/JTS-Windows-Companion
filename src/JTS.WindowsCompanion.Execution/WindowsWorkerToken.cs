using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace JTS.WindowsCompanion.Execution;

[SupportedOSPlatform("windows")]
internal static class WindowsWorkerToken
{
    internal static void Verify(IntPtr process, string expectedSid)
    {
        WindowsNative.Require(WindowsNative.OpenProcessToken(process, 0x0008, out var token));
        using (token) WorkerAccountPolicy.Validate(expectedSid, ReadFacts(token));
    }

    internal static void RestrictServiceCurrent(string expectedSid)
    {
        // No supplied process/token handle: this cannot mutate an installer, parent or remote process.
        WindowsNative.Require(WindowsNative.OpenProcessToken(WindowsNative.GetCurrentProcess(), 0x0088, out var token));
        using (token) ServiceIntegrityRestriction.Apply(expectedSid, () => ReadFacts(token), () => LowerToMedium(token));
    }

    private static WorkerTokenFacts ReadFacts(SafeAccessTokenHandle token)
    {
        using (var user = Read(token, 1))
        using (var groups = Read(token, 2))
        using (var privileges = Read(token, 3))
        using (var elevation = Read(token, 20))
        using (var integrity = Read(token, 25))
        {
            var userSid = new SecurityIdentifier(Marshal.ReadIntPtr(user.Pointer)).Value;
            var integritySid = new SecurityIdentifier(Marshal.ReadIntPtr(integrity.Pointer)).Value;
            if (!int.TryParse(integritySid.Split('-')[^1], NumberStyles.None, CultureInfo.InvariantCulture, out var rid))
                throw new InvalidOperationException("WORKER_TOKEN_INVALID");
            var groupCount = Marshal.ReadInt32(groups.Pointer);
            var privilegeCount = Marshal.ReadInt32(privileges.Pointer);
            // TOKEN_GROUPS uses pointer alignment; TOKEN_PRIVILEGES is DWORD plus LUID_AND_ATTRIBUTES[12].
            if (groupCount is < 0 or > 4096 || 8L + groupCount * 16L > groups.Size
                || privilegeCount is < 0 or > 256 || 4L + privilegeCount * 12L > privileges.Size)
                throw new InvalidOperationException("WORKER_TOKEN_INVALID");
            var groupSids = new string[groupCount];
            for (var i = 0; i < groupCount; i++)
                groupSids[i] = new SecurityIdentifier(Marshal.ReadIntPtr(groups.Pointer, 8 + 16 * i)).Value;
            var names = new string[privilegeCount];
            for (var i = 0; i < privilegeCount; i++)
            {
                var luid = Marshal.PtrToStructure<WindowsNative.Luid>(privileges.Pointer + 4 + 12 * i);
                var size = 0;
                WindowsNative.LookupPrivilegeName(null, ref luid, null, ref size);
                if (size is < 1 or > 256) throw new InvalidOperationException("WORKER_TOKEN_INVALID");
                var name = new StringBuilder(size + 1); size++;
                WindowsNative.Require(WindowsNative.LookupPrivilegeName(null, ref luid, name, ref size));
                names[i] = name.ToString();
            }
            return new WorkerTokenFacts(userSid, Marshal.ReadInt32(elevation.Pointer) != 0, rid, groupSids, names);
        }
    }

    private static void LowerToMedium(SafeAccessTokenHandle token)
    {
        var sid = new SecurityIdentifier("S-1-16-8192");
        var bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0);
        var header = Marshal.SizeOf<WindowsNative.MandatoryLabel>();
        using var buffer = new TokenBuffer(checked(header + bytes.Length));
        var label = new WindowsNative.MandatoryLabel { Sid = buffer.Pointer + header, Attributes = 0x20 }; // SE_GROUP_INTEGRITY.
        Marshal.StructureToPtr(label, buffer.Pointer, false);
        Marshal.Copy(bytes, 0, label.Sid, bytes.Length);
        // TokenIntegrityLevel changes only the primary token label, never groups/privileges/owner or a peer ACL.
        WindowsNative.Require(WindowsNative.SetTokenInformation(token, 25, buffer.Pointer, buffer.Size));
    }

    private static TokenBuffer Read(SafeAccessTokenHandle token, int infoClass)
    {
        WindowsNative.GetTokenInformation(token, infoClass, IntPtr.Zero, 0, out var length);
        if (length is < 4 or > 1_048_576) throw new InvalidOperationException("WORKER_TOKEN_INVALID");
        var buffer = new TokenBuffer(length);
        try { WindowsNative.Require(WindowsNative.GetTokenInformation(token, infoClass, buffer.Pointer, length, out _)); return buffer; }
        catch { buffer.Dispose(); throw; }
    }
    private sealed class TokenBuffer(int size) : IDisposable
    {
        internal IntPtr Pointer { get; } = Marshal.AllocHGlobal(size);
        internal int Size { get; } = size;
        public void Dispose() => Marshal.FreeHGlobal(Pointer);
    }
}
