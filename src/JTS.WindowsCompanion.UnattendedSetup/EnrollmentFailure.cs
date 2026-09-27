namespace JTS.WindowsCompanion.UnattendedSetup;

internal static class EnrollmentFailure
{
    internal static string FromCode(string code) => code switch
    {
        "ENROLLMENT_ACCESS_DENIED" => "Open this connection manager as a signed-in Windows administrator.",
        "ENROLLMENT_SERVICE_UNAVAILABLE" => "The connection service is unavailable or its installed version does not support pairing management. Existing state is preserved. Check its version and local status; do not rerun first installation.",
        "ENROLLMENT_CODE_INVALID" => "The connection code is invalid. Copy the complete code from your Mac.",
        "ENROLLMENT_ORIGIN_MISMATCH" => "This code uses a different relay from this installation. Use a code for the configured relay.",
        "ENROLLMENT_ATTEMPT_ACTIVE" => "A pairing attempt or bound device already exists. Use its status, or revoke it before submitting a new code.",
        "ENROLLMENT_INVITATION_CLOSED" => "This code has already expired or been revoked. Create a new code on your Mac.",
        "ENROLLMENT_RELAY_UNAVAILABLE" => "The relay is unavailable. The saved attempt will resume when it can reconnect.",
        "ENROLLMENT_VERIFICATION_FAILED" => "Device verification failed. Cancel this attempt before using a new code.",
        _ => "Pairing could not be completed. Existing state is preserved. Check the service and retry its status."
    };
}
