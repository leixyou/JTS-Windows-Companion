using System.Globalization;

namespace JTS.WindowsCompanion.Execution;

internal sealed record WorkerTokenFacts(string UserSid, bool Elevated, int IntegrityRid, string[] Groups, string[] Privileges);

internal static class WorkerAccountPolicy
{
    private static readonly HashSet<string> AllowedPrivileges = new(StringComparer.Ordinal)
    { "SeChangeNotifyPrivilege", "SeIncreaseWorkingSetPrivilege", "SeTimeZonePrivilege", "SeShutdownPrivilege", "SeUndockPrivilege" };
    private static readonly HashSet<string> ForbiddenGroups = new(StringComparer.Ordinal)
    { "S-1-5-32-544", "S-1-5-32-547", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551" };

    internal static void ValidateConfiguredSid(string sid)
    {
        var parts = sid.Split('-');
        if (parts.Length != 8 || !sid.StartsWith("S-1-5-21-", StringComparison.Ordinal)
            || parts.Skip(4).Any(p => !uint.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out var value)
                || value.ToString(CultureInfo.InvariantCulture) != p)
            || uint.Parse(parts[7], CultureInfo.InvariantCulture) < 1000)
            throw new ArgumentException("Configure an exact dedicated standard-account SID.", nameof(sid));
    }

    internal static void Validate(string expectedSid, WorkerTokenFacts facts)
    {
        ValidateConfiguredSid(expectedSid);
        if (facts.UserSid != expectedSid || facts.Elevated || facts.IntegrityRid is < 4096 or > 8192
            || facts.Groups.Any(ForbiddenGroups.Contains) || facts.Privileges.Any(p => !AllowedPrivileges.Contains(p)))
            throw new InvalidOperationException("WORKER_ACCOUNT_REJECTED");
    }
}
