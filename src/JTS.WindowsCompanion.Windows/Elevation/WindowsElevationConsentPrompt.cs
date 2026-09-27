using System.Runtime.Versioning;
using System.Text;
using JTS.WindowsCompanion.Elevation;

namespace JTS.WindowsCompanion.Windows.Elevation;

public sealed class WindowsElevationConsentPrompt : IElevationConsentPrompt
{
    public ValueTask<bool> ConfirmAsync(
        ElevatedPowerShellActionDescriptor action,
        TimeSpan duration,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);
        cancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Elevation consent is available only in an interactive Windows session.");
        }

        return ValueTask.FromResult(ConfirmWindows(action, duration, cancellationToken));
    }

    [SupportedOSPlatform("windows")]
    private static bool ConfirmWindows(
        ElevatedPowerShellActionDescriptor action,
        TimeSpan duration,
        CancellationToken cancellationToken)
    {
        var text = new StringBuilder();
        text.AppendLine("JTS Terminal requests a temporary administrator action.");
        text.AppendLine();
        text.AppendLine($"Duration: {duration.TotalMinutes:0.##} minutes (maximum 15)");
        text.AppendLine($"Working directory: {action.WorkingDirectory}");
        text.AppendLine("Data scopes:");
        foreach (var scope in action.DataScopes)
        {
            text.AppendLine($"  [{scope.Access}] {scope.RootId}: {scope.FullPath}");
        }

        text.AppendLine("Environment:");
        if (action.Environment.Count == 0)
        {
            text.AppendLine("  (none)");
        }
        else
        {
            foreach (var pair in action.Environment.OrderBy(pair => pair.Key, StringComparer.Ordinal))
            {
                text.AppendLine($"  {pair.Key}={pair.Value}");
            }
        }

        text.AppendLine();
        text.AppendLine("Full PowerShell script:");
        text.AppendLine("----------------------------------------");
        text.Append(action.Script);
        text.AppendLine();
        text.AppendLine("----------------------------------------");
        text.AppendLine();
        text.AppendLine("Choose Yes only after reviewing the complete script and scopes. Windows UAC will ask separately. JTS cannot type an administrator password or approve the secure desktop.");

        return WindowsConsentDialog.Show(
            "JTS Terminal elevation approval",
            text.ToString(),
            cancellationToken: cancellationToken);
    }
}
