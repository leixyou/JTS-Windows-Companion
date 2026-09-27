using System.Diagnostics;
using System.Text;

namespace JTS.WindowsCompanion.Shell;

internal static class PowerShellUtf8LaunchPlan
{
    // Let the host parse an ASCII-only envelope without depending on its input code page
    // or raw Console.In buffering. -Command also avoids encoded-command CLIXML errors.
    // The UTF-8 user script remains on stdin, never in argv, environment or a temporary file.
    private const string ScriptPlaceholder = "__JTS_SCRIPT_BASE64__";
    private const string Bootstrap = """
        $ProgressPreference = 'SilentlyContinue';
        $utf8 = [Text.UTF8Encoding]::new($false);
        [Console]::OutputEncoding = $utf8;
        $OutputEncoding = $utf8;
        try {
            $jtsScript = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__JTS_SCRIPT_BASE64__'));
            & ([ScriptBlock]::Create($jtsScript + "`nif (-not `$?) { exit 1 }"))
        } catch {
            [Console]::Error.WriteLine($_.ToString());
            exit 1
        }
        """;

    internal static string CreateStandardInput(string script)
    {
        var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(script));
        // One complete compound statement, followed by an empty line for the stdin parser.
        return "& { " + string.Join(" ", Bootstrap.Split('\n').Select(line => line.Trim()))
            .Replace(ScriptPlaceholder, payload, StringComparison.Ordinal) + " }\n\n";
    }

    internal static void Configure(ProcessStartInfo startInfo)
    {
        startInfo.StandardInputEncoding = new UTF8Encoding(false);
        startInfo.StandardOutputEncoding = new UTF8Encoding(false);
        startInfo.StandardErrorEncoding = new UTF8Encoding(false);
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-OutputFormat");
        startInfo.ArgumentList.Add("Text");
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add("-");
    }
}
