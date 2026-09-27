using System.Diagnostics;
using System.Text;

namespace JTS.WindowsCompanion.Shell;

internal static class PowerShellUtf8LaunchPlan
{
    // Only this constant is placed in argv. User scripts stay on the private stdin pipe.
    // Initialize the decoder before reading any script, including non-ASCII identifiers/literals.
    internal const string Bootstrap = """
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        [Console]::InputEncoding = $utf8
        [Console]::OutputEncoding = $utf8
        $OutputEncoding = $utf8
        try {
            $jtsScript = [Console]::In.ReadToEnd()
            & ([ScriptBlock]::Create($jtsScript + "`nif (-not `$?) { exit 1 }"))
        } catch {
            [Console]::Error.WriteLine($_.ToString())
            exit 1
        }
        """;

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
        startInfo.ArgumentList.Add("-EncodedCommand");
        startInfo.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(Bootstrap)));
    }
}
