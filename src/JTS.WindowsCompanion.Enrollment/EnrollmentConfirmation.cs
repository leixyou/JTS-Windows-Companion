using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JTS.WindowsCompanion.Pairing;

namespace JTS.WindowsCompanion.Enrollment;

internal sealed record EnrollmentConfirmation(int Version, string RelayOrigin, string InvitationId,
    string ControllerDeviceId, string PeerDeviceId, string ClaimHash, long ConfirmedAtUnixSeconds,
    long ExpiresAtUnixSeconds, string SignatureBase64)
{
    internal byte[] Transcript() => Encoding.UTF8.GetBytes(string.Join('\n', "JTS-PAIR-CONFIRM-2", RelayOrigin,
        InvitationId, ControllerDeviceId, PeerDeviceId, ClaimHash, ConfirmedAtUnixSeconds.ToString(CultureInfo.InvariantCulture),
        ExpiresAtUnixSeconds.ToString(CultureInfo.InvariantCulture)));

    internal static EnrollmentConfirmation Parse(JsonElement p)
    {
        EnrollmentCrypto.Fields(p, "version", "relayOrigin", "invitationId", "controllerDeviceId", "peerDeviceId",
            "claimHash", "confirmedAtUnixSeconds", "expiresAtUnixSeconds", "signatureBase64");
        return new(p.GetProperty("version").GetInt32(), p.GetProperty("relayOrigin").GetString()!,
            p.GetProperty("invitationId").GetString()!, p.GetProperty("controllerDeviceId").GetString()!,
            p.GetProperty("peerDeviceId").GetString()!, p.GetProperty("claimHash").GetString()!,
            p.GetProperty("confirmedAtUnixSeconds").GetInt64(), p.GetProperty("expiresAtUnixSeconds").GetInt64(),
            p.GetProperty("signatureBase64").GetString()!);
    }

    internal void Verify(EnrollmentAttempt a, RelayDelegatedEnrollment request, string peer, TimeProvider clock)
    {
        if (Version != 2 || RelayOrigin != a.RelayOrigin || InvitationId != a.InvitationId.ToString("D")
            || ControllerDeviceId != request.ControllerDeviceID || PeerDeviceId != peer || ClaimHash != a.ClaimHash
            || ExpiresAtUnixSeconds != request.ExpiresAtUtc.ToUnixTimeSeconds()
            || ExpiresAtUnixSeconds != a.ExpiresAtUnixSeconds || ConfirmedAtUnixSeconds < request.IssuedAtUtc.ToUnixTimeSeconds()
            || ConfirmedAtUnixSeconds >= ExpiresAtUnixSeconds || ConfirmedAtUnixSeconds > clock.GetUtcNow().ToUnixTimeSeconds()) throw Invalid();
        var spki = EnrollmentCrypto.Base64(request.ControllerSPKIBase64, 512);
        using var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(spki, out var used);
        if (used != spki.Length || !key.VerifyData(Transcript(), EnrollmentCrypto.Base64(SignatureBase64, 64),
                HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) throw Invalid();
    }
    private static EnrollmentException Invalid() => new("ENROLLMENT_CONFIRMATION_INVALID");
}
