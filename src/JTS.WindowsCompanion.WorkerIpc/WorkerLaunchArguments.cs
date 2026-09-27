using System.Globalization;

namespace JTS.WindowsCompanion.WorkerIpc;

/// <summary>Public rendezvous metadata only. Payloads, passwords and grants never appear in SCM arguments.</summary>
public static class WorkerLaunchArguments
{
    public const string ServiceName = "JTSCompanionWorker25";
    public static string[] Encode(WorkerLaunchDescriptor descriptor)
    {
        var result = new[] { descriptor.SessionId.ToString("D"), descriptor.Authority.ProcessId.ToString(CultureInfo.InvariantCulture),
            descriptor.Authority.StartedFileTime.ToString(CultureInfo.InvariantCulture), descriptor.Authority.AccountSid,
            descriptor.Authority.ImagePath, descriptor.Authority.ImageSha256, descriptor.WorkerSid };
        _ = Decode(result); return result;
    }
    public static WorkerLaunchDescriptor Decode(IReadOnlyList<string> args)
    {
        if (args.Count != 7 || args.Any(a => a is null || a.Length is 0 or > 1024 || a.Contains('\0'))
            || !Guid.TryParseExact(args[0], "D", out var session) || session == Guid.Empty || session.ToString("D") != args[0]
            || !uint.TryParse(args[1], NumberStyles.None, CultureInfo.InvariantCulture, out var pid) || pid == 0
            || pid.ToString(CultureInfo.InvariantCulture) != args[1]
            || !long.TryParse(args[2], NumberStyles.None, CultureInfo.InvariantCulture, out var started) || started <= 0
            || started.ToString(CultureInfo.InvariantCulture) != args[2]
            || args[5].Length != 64 || !args[5].All(c => c is >= 'a' and <= 'f' or >= '0' and <= '9')
            || !CanonicalSid(args[3]) || !CanonicalSid(args[6]) || args[3] == args[6]
            || args[4].Length < 4 || !char.IsAsciiLetter(args[4][0]) || args[4][1] != ':' || args[4][2] != '\\'
            || args[4].Any(c => c < 32 || c is '"' or '|')) throw new ArgumentException("WORKER_LAUNCH_INVALID");
        return new WorkerLaunchDescriptor(session, new WindowsProcessIdentity(pid, started, args[3], args[4], args[5]), args[6]);
    }
    private static bool CanonicalSid(string value)
    {
        var parts = value.Split('-');
        return parts.Length is 8 or 9 && value.StartsWith("S-1-5-", StringComparison.Ordinal)
            && ((parts[3] == "21" && parts.Length == 8) || (parts[3] == "80" && parts.Length == 9))
            && parts.Skip(4).All(p => uint.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out var n)
                && n.ToString(CultureInfo.InvariantCulture) == p);
    }
}
