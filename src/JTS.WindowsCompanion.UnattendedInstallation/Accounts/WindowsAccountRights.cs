using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace JTS.WindowsCompanion.UnattendedInstallation;

[SupportedOSPlatform("windows")]
internal sealed class WindowsAccountRights : IDisposable
{
    private static readonly string[] Required = ["SeServiceLogonRight", "SeDenyInteractiveLogonRight",
        "SeDenyRemoteInteractiveLogonRight", "SeDenyNetworkLogonRight", "SeDenyBatchLogonRight"];
    private IntPtr _policy;
    internal WindowsAccountRights()
    {
        var attributes = new LocalAccountNative.LsaObjectAttributes { Length = (uint)Marshal.SizeOf<LocalAccountNative.LsaObjectAttributes>() };
        // POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT; no broad POLICY_ALL_ACCESS.
        if (LocalAccountNative.LsaOpenPolicy(IntPtr.Zero, ref attributes, 0x810, out _policy) != 0 || _policy == IntPtr.Zero)
        {
            Dispose();
            throw new UnattendedInstallationException("INSTALL_ACCOUNT_POLICY_OPEN_FAILED");
        }
    }

    internal void RequireExpected(string sid, bool complete)
    {
        var actual = Read(sid);
        if (actual.Except(Required, StringComparer.Ordinal).Any()
            || (complete && Required.Except(actual, StringComparer.Ordinal).Any()))
            throw new UnattendedInstallationException("INSTALL_ACCOUNT_RIGHTS_REJECTED");
    }

    internal void GrantServiceOnly(string sid)
    {
        RequireExpected(sid, complete: false);
        var rights = new LocalAccountNative.LsaString[Required.Length];
        try
        {
            for (var i = 0; i < rights.Length; i++) rights[i] = new LocalAccountNative.LsaString
            {
                Buffer = Marshal.StringToHGlobalUni(Required[i]), Length = checked((ushort)(Required[i].Length * sizeof(char))),
                MaximumLength = checked((ushort)((Required[i].Length + 1) * sizeof(char))),
            };
            if (LocalAccountNative.LsaAddAccountRights(_policy, SidBytes(sid), rights, (uint)rights.Length) != 0)
                throw new UnattendedInstallationException("INSTALL_ACCOUNT_RIGHTS_FAILED");
            RequireExpected(sid, complete: true);
        }
        finally { foreach (var right in rights) if (right.Buffer != IntPtr.Zero) Marshal.FreeHGlobal(right.Buffer); }
    }

    internal void RemoveOwned(string sid)
    {
        RequireExpected(sid, complete: false);
        if (Read(sid).Count == 0) return;
        if (LocalAccountNative.LsaRemoveAccountRights(_policy, SidBytes(sid), true, IntPtr.Zero, 0) != 0)
            throw new UnattendedInstallationException("INSTALL_ACCOUNT_RIGHTS_REMOVE_FAILED");
        if (Read(sid).Count != 0) throw new UnattendedInstallationException("INSTALL_ACCOUNT_RIGHTS_REMOVE_FAILED");
    }

    private HashSet<string> Read(string sid)
    {
        var status = LocalAccountNative.LsaEnumerateAccountRights(_policy, SidBytes(sid), out var buffer, out var count);
        try
        {
            // STATUS_OBJECT_NAME_NOT_FOUND means no LSA rights entry exists for this SID.
            if (status == 0xC0000034) return new HashSet<string>(StringComparer.Ordinal);
            if (status != 0 || count > 64 || (count != 0 && buffer == IntPtr.Zero))
                throw new UnattendedInstallationException("INSTALL_ACCOUNT_RIGHTS_QUERY_FAILED");
            var result = new HashSet<string>(StringComparer.Ordinal);
            for (var i = 0; i < count; i++)
            {
                var value = Marshal.PtrToStructure<LocalAccountNative.LsaString>(buffer + checked((int)i * Marshal.SizeOf<LocalAccountNative.LsaString>()));
                if (value.Buffer == IntPtr.Zero || value.Length is 0 or > 1024 || value.Length % 2 != 0 || value.Length > value.MaximumLength
                    || !result.Add(Marshal.PtrToStringUni(value.Buffer, value.Length / sizeof(char))!))
                    throw new UnattendedInstallationException("INSTALL_ACCOUNT_RIGHTS_QUERY_FAILED");
            }
            return result;
        }
        finally { if (buffer != IntPtr.Zero) _ = LocalAccountNative.LsaFreeMemory(buffer); }
    }

    private static byte[] SidBytes(string sid)
    {
        var identity = new SecurityIdentifier(sid); var bytes = new byte[identity.BinaryLength];
        identity.GetBinaryForm(bytes, 0); return bytes;
    }
    public void Dispose()
    {
        var policy = Interlocked.Exchange(ref _policy, IntPtr.Zero);
        if (policy != IntPtr.Zero) _ = LocalAccountNative.LsaClose(policy);
    }
}
