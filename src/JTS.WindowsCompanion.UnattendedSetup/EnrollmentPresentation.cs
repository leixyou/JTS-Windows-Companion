namespace JTS.WindowsCompanion.UnattendedSetup;

internal sealed record EnrollmentPresentation(string Pairing, string Detail, bool MaySubmit, bool MayRevoke)
{
    internal const string RdpStatus = "RDP login: not checked. Pairing and Windows login are separate. A failed RDP login does not consume an unbound, unexpired code or revoke a bound device.";
    internal static EnrollmentPresentation From(string state, bool hasInvitation) => state switch
    {
        "bound" => new("Device paired", "The device stays bound for reconnects until you revoke access. You do not need another code for an RDP login retry.", false, hasInvitation),
        "pending" => new("Pairing in progress", "The code is saved by the protected service. It will continue when the relay is reachable; keep the same code rather than creating another attempt.", false, hasInvitation),
        "claimed" => new("Finishing device binding", "The endpoint identities are being verified. Windows login is not part of code consumption.", false, hasInvitation),
        "committing" => new("Saving device binding", "The verified device permissions are being saved. This operation resumes automatically if interrupted.", false, hasInvitation),
        "revoking" => new("Revoking access", "The service is removing this binding and closing its active channels. Wait for revocation to finish before using another code.", false, false),
        "cancelled" or "revoked" => new("Access revoked", "Paste a new code to authorize another binding.", true, false),
        "expired" => new("Code expired", "The unbound code expired. Create a fresh code on your Mac and paste it here.", true, false),
        "idle" => new("No device paired", "Paste the one-use code from your AI-enabled Mac device. No additional pairing approval is needed.", true, false),
        _ => new("Pairing unavailable", "The protected service could not report its state. Existing credentials have not been cleared. Check the service before retrying.", false, hasInvitation),
    };
}
