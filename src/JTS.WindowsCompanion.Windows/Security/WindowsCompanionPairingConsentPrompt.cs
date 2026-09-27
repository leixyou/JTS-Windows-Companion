using System.Runtime.Versioning;
using System.Text;
using JTS.WindowsCompanion.Security;
using JTS.WindowsCompanion.Windows.Elevation;

namespace JTS.WindowsCompanion.Windows.Security;

public sealed class WindowsCompanionPairingConsentPrompt : ICompanionPairingConsentPrompt
{
    public async ValueTask<bool> ConfirmAsync(
        CompanionPeerIdentity peer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(peer);
        cancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Companion pairing consent is available only in an interactive Windows session.");
        }

        return await ConfirmOnWindowsAsync(peer, cancellationToken).ConfigureAwait(false);
    }

    [SupportedOSPlatform("windows")]
    private static Task<bool> ConfirmOnWindowsAsync(CompanionPeerIdentity peer, CancellationToken cancellationToken) =>
        Task.Run(() => ConfirmWindows(peer, cancellationToken), cancellationToken);

    [SupportedOSPlatform("windows")]
    private static bool ConfirmWindows(CompanionPeerIdentity peer, CancellationToken cancellationToken)
    {
        var text = new StringBuilder();
        text.AppendLine("JTS Terminal requests structured access to this Windows account.");
        text.AppendLine();
        text.AppendLine($"Mac device ID: {peer.DeviceId:D}");
        text.AppendLine("Mac P-256 public-key fingerprint (SHA-256):");
        text.AppendLine(peer.FingerprintSha256);
        text.AppendLine();
        text.AppendLine("Approve only if this fingerprint exactly matches the fingerprint currently shown by JTS Terminal on the Mac.");
        text.AppendLine();
        text.AppendLine("Approval is stored for this Windows user with DPAPI. It enables the listed Mac identity to invoke structured UI Automation, scoped files, shell, worker, transfer, elevation, and managed-service methods over this RDP Dynamic Virtual Channel. A different key will be rejected and cannot replace this approval.");

        return WindowsConsentDialog.Show(
            "JTS Terminal Companion pairing",
            text.ToString(),
            instructionText: "Compare the complete SHA-256 fingerprint on Windows and the Mac before approving structured access.",
            approveButtonText: "Approve this Mac",
            cancellationToken: cancellationToken);
    }
}
