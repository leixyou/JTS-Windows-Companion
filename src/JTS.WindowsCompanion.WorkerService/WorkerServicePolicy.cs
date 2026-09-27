using System.Globalization;
using JTS.WindowsCompanion.WorkerIpc;

namespace JTS.WindowsCompanion.WorkerService;

public sealed class WorkerServiceInstallation
{
    public string ExecutablePath { get; }
    public string AccountName { get; }
    public string AccountSid { get; }
    public WorkerServiceInstallation(string executablePath, string localAccountName, string accountSid)
    {
        if (!LocalExecutable(executablePath) || localAccountName is not { Length: >= 3 and <= 22 }
            || !localAccountName.StartsWith(@".\", StringComparison.Ordinal)
            || !localAccountName[2..].All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-') || !DedicatedSid(accountSid))
            throw new ArgumentException("WORKER_INSTALLATION_INVALID");
        ExecutablePath = executablePath; AccountName = localAccountName; AccountSid = accountSid;
    }
    private static bool LocalExecutable(string path) => path is { Length: >= 4 and <= 240 }
        && char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == '\\'
        && !path.Any(c => c < 32 || c is '"' or '/' or '?' or '*')
        && path[2..].IndexOf(':') < 0 && path.Split('\\').All(p => p is not ("." or "..") && !p.EndsWith(' ') && !p.EndsWith('.'))
        && path.EndsWith(@"\JTS.WindowsCompanion.WorkerRunner.exe", StringComparison.OrdinalIgnoreCase);
    private static bool DedicatedSid(string sid)
    {
        var p = sid.Split('-');
        return p.Length == 8 && sid.StartsWith("S-1-5-21-", StringComparison.Ordinal)
            && p.Skip(4).All(v => uint.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n.ToString(CultureInfo.InvariantCulture) == v)
            && uint.Parse(p[7], CultureInfo.InvariantCulture) >= 1000;
    }
}

internal sealed class WorkerServiceException(string code) : InvalidOperationException(code)
{ internal string Code { get; } = code; }
internal sealed record AccessEntry(string Sid, int Mask, bool Allow, bool InheritOnly = false);
internal sealed record SecurityFacts(string Owner, bool Protected, AccessEntry[] Entries);
internal sealed record ServiceFacts(uint Type, uint StartType, string Command, string AccountName, string AccountSid,
    string[] RequiredPrivileges, uint ServiceSidType, bool RecoveryActions, bool FailureFlag, uint Triggers, bool DelayedStart, SecurityFacts Security);
internal sealed record ServiceState(uint State, uint ProcessId, uint Type = 0x10, uint Flags = 0);

internal static class WorkerServicePolicy
{
    internal const int AuthorityServiceRights = 0x00020035; // QUERY_CONFIG, QUERY_STATUS, START, STOP, READ_CONTROL.
    internal const string SystemSid = "S-1-5-18", AdminSid = "S-1-5-32-544";
    internal const string InstallerSid = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    internal static void Validate(WorkerServiceInstallation expected, string authoritySid, ServiceFacts actual)
    {
        if (authoritySid == expected.AccountSid || actual.Type != 0x10 || actual.StartType != 3
            || !string.Equals(actual.Command, '"' + expected.ExecutablePath + "\" --service", StringComparison.OrdinalIgnoreCase)
            || !actual.Command.EndsWith("\" --service", StringComparison.Ordinal)
            || !string.Equals(actual.AccountName, expected.AccountName, StringComparison.OrdinalIgnoreCase)
            || actual.AccountSid != expected.AccountSid || actual.ServiceSidType != 1 || actual.RecoveryActions
            || actual.FailureFlag || actual.Triggers != 0 || actual.DelayedStart
            || actual.RequiredPrivileges.Length != 1 || actual.RequiredPrivileges[0] != "SeChangeNotifyPrivilege")
            throw new WorkerServiceException("WORKER_SERVICE_POLICY_REJECTED");
        var security = actual.Security;
        if (!security.Protected || security.Owner is not (SystemSid or AdminSid)) throw new WorkerServiceException("WORKER_SERVICE_ACL_REJECTED");
        var authorityPresent = false;
        foreach (var ace in security.Entries)
        {
            if (!ace.Allow || ace.InheritOnly) throw new WorkerServiceException("WORKER_SERVICE_ACL_REJECTED");
            if (ace.Sid is SystemSid or AdminSid) continue;
            if (ace.Sid != authoritySid || ace.Mask != AuthorityServiceRights || authorityPresent)
                throw new WorkerServiceException("WORKER_SERVICE_ACL_REJECTED");
            authorityPresent = true;
        }
        if (!authorityPresent) throw new WorkerServiceException("WORKER_SERVICE_ACL_REJECTED");
    }
    internal static void ValidateProgramObject(SecurityFacts security, bool canCreateContent)
    {
        if (security.Owner is not (SystemSid or AdminSid or InstallerSid)) throw new WorkerServiceException("WORKER_PROGRAM_OWNER_REJECTED");
        const int changeIdentity = 0x10000000 | 0x40000000 | 0x000D0040; // GENERIC_ALL/WRITE, WRITE_DAC/OWNER, DELETE/DELETE_CHILD.
        var mutation = changeIdentity | (canCreateContent ? 0x00000116 : 0);
        if (security.Entries.Any(a => a.Allow && !a.InheritOnly && a.Sid is not (SystemSid or AdminSid or InstallerSid) && (a.Mask & mutation) != 0))
            throw new WorkerServiceException("WORKER_PROGRAM_WRITABLE");
    }
    internal static void RequireStopped(ServiceState state)
    {
        if (state.State != 1 || state.ProcessId != 0 || state.Type != 0x10 || state.Flags != 0)
            throw new WorkerServiceException("WORKER_SERVICE_BUSY");
    }
}
