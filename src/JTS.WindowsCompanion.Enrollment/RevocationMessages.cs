using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace JTS.WindowsCompanion.Enrollment;

internal sealed record RevocationRequest(int Version, string RevocationId, string RelayOrigin, string ControllerDeviceId,
    string PeerDeviceId, string PairingId, string GrantId, string FileGrantId, string RdpGrantId, long RequestedAtUnixSeconds, string SignatureBase64)
{
    internal byte[] Transcript() => Encoding.UTF8.GetBytes(string.Join('\n', "JTS-PAIR-REVOKE-2", RevocationId, RelayOrigin,
        ControllerDeviceId, PeerDeviceId, PairingId, GrantId, FileGrantId, RdpGrantId, RequestedAtUnixSeconds.ToString(CultureInfo.InvariantCulture)));
    internal string RequestHash => EnrollmentCrypto.Hash([.. Transcript(), .. EnrollmentCrypto.Base64(SignatureBase64, 64)]);
    internal static RevocationRequest Parse(JsonElement p)
    {
        EnrollmentCrypto.Fields(p, "version", "revocationId", "relayOrigin", "controllerDeviceId", "peerDeviceId", "pairingId",
            "grantId", "fileGrantId", "rdpGrantId", "requestedAtUnixSeconds", "signatureBase64");
        return new(p.GetProperty("version").GetInt32(), Text(p, "revocationId"), Text(p, "relayOrigin"), Text(p, "controllerDeviceId"),
            Text(p, "peerDeviceId"), Text(p, "pairingId"), Text(p, "grantId"), Text(p, "fileGrantId"), Text(p, "rdpGrantId"),
            p.GetProperty("requestedAtUnixSeconds").GetInt64(), Text(p, "signatureBase64"));
    }
    internal void Verify(string origin, string peer, string spki)
    {
        if (Version != 2 || RelayOrigin != origin || PeerDeviceId != peer || RequestedAtUnixSeconds is < 1 or > 253402300799
            || !IsHash(ControllerDeviceId) || !IsHash(PeerDeviceId)) throw Invalid();
        foreach (var id in new[] { RevocationId, PairingId, GrantId, FileGrantId, RdpGrantId }) _ = Id(id);
        if (new[] { PairingId, GrantId, FileGrantId, RdpGrantId }.Distinct().Count() != 4) throw Invalid();
        var bytes = EnrollmentCrypto.Base64(spki, 512); if (EnrollmentCrypto.Hash(bytes) != ControllerDeviceId) throw Invalid();
        using var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(bytes, out var used);
        if (used != bytes.Length || key.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7"
            || !key.VerifyData(Transcript(), EnrollmentCrypto.Base64(SignatureBase64, 64), HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) throw Invalid();
    }
    internal static Guid Id(string text) => Guid.TryParseExact(text, "D", out var id) && id != Guid.Empty && id.ToString("D") == text ? id : throw Invalid();
    internal static bool IsHash(string text) => text is { Length: 64 } && text.All(c => "0123456789abcdef".Contains(c));
    private static string Text(JsonElement p, string name) => p.GetProperty(name).GetString() ?? throw Invalid();
    internal static EnrollmentException Invalid() => new("REVOCATION_VERIFICATION_FAILED");
}

internal sealed record RevocationReceipt(int Version, string RevocationId, string RequestHash, string ControllerDeviceId,
    string PeerDeviceId, long RevokedAtUnixSeconds, string SignatureBase64)
{
    internal byte[] Transcript() => Encoding.UTF8.GetBytes(string.Join('\n', "JTS-PAIR-REVOKED-2", RevocationId, RequestHash,
        ControllerDeviceId, PeerDeviceId, RevokedAtUnixSeconds.ToString(CultureInfo.InvariantCulture)));
}

internal sealed record RevocationDelivery(RevocationRequest Revocation, string ControllerSPKIBase64);
