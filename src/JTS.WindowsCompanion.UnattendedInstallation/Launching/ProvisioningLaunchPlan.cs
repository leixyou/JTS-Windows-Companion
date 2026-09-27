namespace JTS.WindowsCompanion.UnattendedInstallation;

internal static class ProvisioningLaunchPlan
{
    internal const string FileName = "JTS.WindowsCompanion.AuthorityProvisioner.exe";
    internal static readonly TimeSpan ExecutionLimit = TimeSpan.FromMinutes(2);
    internal static readonly TimeSpan DrainLimit = TimeSpan.FromSeconds(10);

    internal static string CommandLine(LocalAccountIdentity authority, string executable)
    {
        authority.Validate();
        if (authority.Role != "authority" || !IsLocalPath(executable)
            || !executable.EndsWith("\\" + FileName, StringComparison.OrdinalIgnoreCase))
            throw new UnattendedInstallationException("PROVISION_LAUNCH_INPUT_REJECTED");
        return "\"" + executable + "\" --provision " + authority.EnrollmentId.ToString("D");
    }

    internal static string EnvironmentBlock(string system, string windows, string profile,
        string programData, string account, string computer)
    {
        if (new[] { system, windows, profile, programData }.Any(p => !IsLocalPath(p))
            || new[] { account, computer }.Any(p => string.IsNullOrWhiteSpace(p) || p.Any(c => char.IsControl(c) || c == '=')))
            throw new UnattendedInstallationException("PROVISION_ENVIRONMENT_REJECTED");
        // No caller/user-registry environment inheritance: especially no CLR/profiler/startup-hook or PATH injection.
        var values = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["SystemRoot"] = windows, ["WINDIR"] = windows, ["SystemDrive"] = windows[..2],
            ["PATH"] = system, ["ProgramData"] = programData, ["USERPROFILE"] = profile,
            ["LOCALAPPDATA"] = profile.TrimEnd('\\') + "\\AppData\\Local",
            ["APPDATA"] = profile.TrimEnd('\\') + "\\AppData\\Roaming",
            ["TEMP"] = profile.TrimEnd('\\') + "\\AppData\\Local\\Temp",
            ["TMP"] = profile.TrimEnd('\\') + "\\AppData\\Local\\Temp",
            ["USERNAME"] = account, ["USERDOMAIN"] = computer,
            ["DOTNET_EnableDiagnostics"] = "0", ["DOTNET_MULTILEVEL_LOOKUP"] = "0",
        };
        return string.Join('\0', values.Select(p => p.Key + "=" + p.Value)) + "\0\0";
    }

    private static bool IsLocalPath(string path) => path.Length is >= 3 and <= 240
        && char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == '\\'
        && !path.Any(c => char.IsControl(c) || c is '"' or '/' or '=')
        && !path[2..].Contains(':') && !path.Split('\\').Any(p => p is "." or "..");
}
