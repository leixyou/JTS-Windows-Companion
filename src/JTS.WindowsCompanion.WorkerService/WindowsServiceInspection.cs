using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace JTS.WindowsCompanion.WorkerService;

[SupportedOSPlatform("windows")]
internal sealed class WindowsServiceInspection : IDisposable
{
    internal ServiceHandle Service { get; }
    internal WindowsServiceInspection()
    {
        using var manager = ScmNative.OpenManager(null, null, 1);
        ScmNative.Require(!manager.IsInvalid);
        Service = ScmNative.OpenService(manager, WorkerIpc.WorkerLaunchArguments.ServiceName, WorkerServicePolicy.AuthorityServiceRights);
        ScmNative.Require(!Service.IsInvalid);
    }
    internal ServiceFacts ReadFacts(WorkerServiceInstallation expected)
    {
        using var configuration = Query(0); var config = configuration.Structure<ScmNative.Configuration>();
        var account = configuration.String(config.Account);
        // Reject a different configured account before attempting any domain account resolution.
        if (!string.Equals(account, expected.AccountName, StringComparison.OrdinalIgnoreCase)) throw new WorkerServiceException("WORKER_SERVICE_ACCOUNT_REJECTED");
        var sid = ((SecurityIdentifier)new NTAccount(Environment.MachineName, account[2..]).Translate(typeof(SecurityIdentifier))).Value;
        using var privileges = Query(6); using var recovery = Query(2); using var failureFlag = Query(4);
        using var serviceSid = Query(5); using var triggers = Query(8); using var delayed = Query(3);
        var actions = recovery.Structure<ScmNative.Recovery>();
        using var security = Query(-1);
        return new ServiceFacts(config.Type, config.StartType, configuration.String(config.BinaryPath), account, sid,
            privileges.MultiString(privileges.Structure<IntPtr>()), serviceSid.Structure<uint>(), actions.Count != 0
            || recovery.String(actions.Reboot).Length != 0 || recovery.String(actions.Command).Length != 0,
            failureFlag.Structure<uint>() != 0, triggers.Structure<uint>(), delayed.Structure<uint>() != 0, ParseSecurity(security.Pointer, security.Size));
    }
    internal ServiceState ReadState()
    {
        ScmNative.Require(ScmNative.QueryServiceStatusEx(Service, 0, out var state, Marshal.SizeOf<ScmNative.Status>(), out _));
        return new ServiceState(state.State, state.Pid, state.Type, state.Flags);
    }
    private ScmBuffer Query(int kind)
    {
        var needed = 0;
        bool Call(IntPtr pointer, int size) => kind switch
        {
            0 => ScmNative.QueryConfig(Service, pointer, size, out needed),
            -1 => ScmNative.QueryServiceObjectSecurity(Service, 5, pointer, size, out needed),
            _ => ScmNative.QueryConfig2(Service, kind, pointer, size, out needed),
        };
        _ = Call(IntPtr.Zero, 0);
        if (needed is < 4 or > 65536 || (kind != -1 && needed > 8192)) throw new WorkerServiceException("WORKER_SCM_DATA_INVALID");
        var buffer = new ScmBuffer(needed);
        try { ScmNative.Require(Call(buffer.Pointer, buffer.Size)); return buffer; }
        catch { buffer.Dispose(); throw; }
    }
    internal static void VerifyProgramAcl(string executable)
    {
        var programFiles = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)).TrimEnd('\\');
        var full = Path.GetFullPath(executable);
        if (!full.StartsWith(programFiles + "\\", StringComparison.OrdinalIgnoreCase)) throw new WorkerServiceException("WORKER_PROGRAM_LOCATION_REJECTED");
        // Existing ancestors must not be replaceable; leaf directory/file must not accept new/changed content from untrusted accounts.
        var current = full; var leafDirectory = Path.GetDirectoryName(full);
        do
        {
            ScmNative.Require(ScmNative.GetNamedSecurityInfo(current, 1, 5, out _, out _, out _, out _, out var descriptor) == 0);
            try
            {
                WorkerServicePolicy.ValidateProgramObject(ParseSecurity(descriptor, checked((int)ScmNative.GetSecurityDescriptorLength(descriptor))),
                    current == full || current == leafDirectory);
            }
            finally { ScmNative.LocalFree(descriptor); }
            current = Path.GetDirectoryName(current);
        } while (!string.IsNullOrEmpty(current));
        if (File.Exists(Path.ChangeExtension(full, ".dll")) || File.Exists(Path.ChangeExtension(full, ".runtimeconfig.json")))
            throw new WorkerServiceException("WORKER_SINGLE_FILE_REQUIRED");
    }
    private static SecurityFacts ParseSecurity(IntPtr pointer, int size)
    {
        if (pointer == IntPtr.Zero || size is < 20 or > 65536) throw new WorkerServiceException("WORKER_ACL_INVALID");
        var bytes = new byte[size]; Marshal.Copy(pointer, bytes, 0, size);
        var security = new RawSecurityDescriptor(bytes, 0);
        if (security.Owner is null || security.DiscretionaryAcl is null) throw new WorkerServiceException("WORKER_ACL_INVALID");
        var entries = new List<AccessEntry>();
        foreach (var item in security.DiscretionaryAcl)
        {
            if (item is not CommonAce ace || ace.IsCallback || ace.AceQualifier is not (AceQualifier.AccessAllowed or AceQualifier.AccessDenied))
                throw new WorkerServiceException("WORKER_ACL_INVALID");
            entries.Add(new AccessEntry(ace.SecurityIdentifier.Value, ace.AccessMask, ace.AceQualifier == AceQualifier.AccessAllowed,
                (ace.AceFlags & AceFlags.InheritOnly) != 0));
        }
        return new SecurityFacts(security.Owner.Value, (security.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0, entries.ToArray());
    }
    public void Dispose() => Service.Dispose();
}
