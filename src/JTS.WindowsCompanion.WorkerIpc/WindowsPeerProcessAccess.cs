using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace JTS.WindowsCompanion.WorkerIpc;

/// <summary>Only the current process/token are modified; no remote process or VM/token-duplication rights are granted.</summary>
[SupportedOSPlatform("windows")]
internal static class WindowsPeerProcessAccess
{
    private static readonly object Gate = new();
    private static readonly HashSet<(string Sid, bool Supervision)> Installed = [];
    internal static void AllowCurrentPeer(string peerSid, bool supervision)
    {
        VerifiedWindowsProcess.ValidateSid(peerSid);
        lock (Gate)
        {
            if (Installed.Contains((peerSid, supervision))) return;
            using var process = WindowsIpcNative.OpenProcess(0x00061000, false, (uint)Environment.ProcessId);
            WindowsIpcNative.Require(!process.IsInvalid);
            // QUERY_LIMITED_INFORMATION | SYNCHRONIZE; authority additionally gets TERMINATE | SET_QUOTA.
            Grant(process, peerSid, 0x00101000 | (supervision ? 0x101 : 0));
            WindowsIpcNative.Require(WindowsIpcNative.OpenProcessToken(process, 0x00060008, out var token));
            using (token) Grant(token, peerSid, 8); // TOKEN_QUERY only, never DUPLICATE/IMPERSONATE/ASSIGN_PRIMARY.
            Installed.Add((peerSid, supervision));
        }
    }
    private static void Grant(SafeHandle handle, string sid, int rights)
    {
        var code = GetSecurityInfo(handle, 6, 4, out _, out _, out _, out _, out var pointer);
        WindowsIpcNative.Require(code == 0 && pointer != IntPtr.Zero);
        try
        {
            var size = checked((int)GetSecurityDescriptorLength(pointer));
            if (size is < 20 or > 65536) throw new WorkerIpcException();
            var bytes = new byte[size]; Marshal.Copy(pointer, bytes, 0, size);
            var security = new RawSecurityDescriptor(bytes, 0);
            var acl = security.DiscretionaryAcl ?? throw new WorkerIpcException();
            var peer = new SecurityIdentifier(sid);
            for (var i = 0; i < acl.Count; i++)
                if (acl[i] is CommonAce ace && ace.SecurityIdentifier == peer)
                    throw new WorkerIpcException(); // Unexpected pre-existing peer rights must be audited, not merged silently.
            var insertion = 0;
            while (insertion < acl.Count && acl[insertion] is CommonAce existing && existing.AceQualifier == AceQualifier.AccessDenied) insertion++;
            acl.InsertAce(insertion, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, rights, peer, false, null));
            var encoded = new byte[acl.BinaryLength]; acl.GetBinaryForm(encoded, 0);
            var dacl = Marshal.AllocHGlobal(encoded.Length);
            try
            {
                Marshal.Copy(encoded, 0, dacl, encoded.Length);
                WindowsIpcNative.Require(SetSecurityInfo(handle, 6, 4, IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero) == 0);
            }
            finally { Marshal.FreeHGlobal(dacl); }
        }
        finally { WindowsIpcNative.LocalFree(pointer); }
    }
    [DllImport("advapi32.dll")] private static extern uint GetSecurityInfo(SafeHandle handle, int objectType, uint info,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")] private static extern uint SetSecurityInfo(SafeHandle handle, int objectType, uint info,
        IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
}
