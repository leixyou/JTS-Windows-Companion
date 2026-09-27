namespace JTS.WindowsCompanion.Execution;

internal static class PowerShellLaunchPlan
{
    // Constant bootstrap only; the user script is never placed in argv, environment or a temporary file.
    internal const string Bootstrap = """
        $ProgressPreference = 'SilentlyContinue';
        $utf8 = [Text.UTF8Encoding]::new($false);
        [Console]::InputEncoding = $utf8;
        [Console]::OutputEncoding = $utf8;
        $OutputEncoding = $utf8;
        $ErrorActionPreference = 'Stop';
        try {
            Import-Module -Name ($PSHOME + '/Modules/Microsoft.PowerShell.Utility/Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop;
            Import-Module -Name ($PSHOME + '/Modules/Microsoft.PowerShell.Management/Microsoft.PowerShell.Management.psd1') -ErrorAction Stop;
            $code = [Console]::In.ReadToEnd();
            $global:LASTEXITCODE = 0;
            & ([ScriptBlock]::Create($code));
            if (-not $?) { exit 1 };
            exit $global:LASTEXITCODE;
        } catch {
            [Console]::Error.WriteLine($_.ToString());
            exit 1;
        }
        """;
    // The fixed bootstrap contains no double quotes or user data. A normal command
    // avoids encoded-command CLIXML serialization of nonterminating error records.
    internal static string Arguments => "-NoLogo -NoProfile -NonInteractive -OutputFormat Text -Command \""
        + Bootstrap.ReplaceLineEndings(" ") + "\"";

    internal static string EnvironmentBlock(string systemDirectory, string windowsDirectory, string profile, string localData)
    {
        if (new[] { systemDirectory, windowsDirectory, profile, localData }.Any(p => !PowerShellRequest.IsLocalDirectory(p)))
            throw new InvalidOperationException("WORKER_ENVIRONMENT_INVALID");
        // Deliberately do not copy parent environment (tokens, PSModulePath, profiler hooks, etc.).
        var values = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["SystemRoot"] = windowsDirectory, ["WINDIR"] = windowsDirectory,
            ["SystemDrive"] = windowsDirectory[..2],
            ["COMSPEC"] = systemDirectory.TrimEnd('\\') + @"\cmd.exe",
            ["PATH"] = string.Join(';', systemDirectory, windowsDirectory, systemDirectory.TrimEnd('\\') + @"\WindowsPowerShell\v1.0"),
            ["PSModulePath"] = systemDirectory.TrimEnd('\\') + @"\WindowsPowerShell\v1.0\Modules",
            ["USERPROFILE"] = profile, ["LOCALAPPDATA"] = localData,
            ["TEMP"] = localData.TrimEnd('\\') + @"\Temp", ["TMP"] = localData.TrimEnd('\\') + @"\Temp",
        };
        if (values.Values.Any(v => string.IsNullOrWhiteSpace(v) || v.Contains('\0'))) throw new InvalidOperationException("WORKER_ENVIRONMENT_INVALID");
        return string.Join('\0', values.Select(p => p.Key + "=" + p.Value)) + "\0\0";
    }
}
