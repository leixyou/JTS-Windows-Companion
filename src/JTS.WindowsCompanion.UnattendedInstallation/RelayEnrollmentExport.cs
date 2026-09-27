using System.Text.Json;
using JTS.WindowsCompanion.Pairing;

namespace JTS.WindowsCompanion.UnattendedInstallation;

internal static class RelayEnrollmentExport
{
    internal static string Create(string name, string relayOrigin, string? publicKeySpki, string? deviceId, RelayDelegatedEnrollment delegation)
    {
        if (string.IsNullOrEmpty(publicKeySpki) || string.IsNullOrEmpty(deviceId))
            throw new UnattendedInstallationException("INSTALL_PUBLIC_ENROLLMENT_MISSING");
        return JsonSerializer.Serialize(new { version = 1, name,
            installationState = "installedAwaitingRelayAdmission", relayURL = relayOrigin,
            peerSPKIBase64 = publicKeySpki, peerDeviceID = deviceId,
            pairingID = delegation.PairingID, grantID = delegation.GrantID, fileGrantID = delegation.FileGrantID, rdpGrantID = delegation.RdpGrantID,
            allowWindows10TLS12 = delegation.AllowWindows10TLS12 });
    }
}
