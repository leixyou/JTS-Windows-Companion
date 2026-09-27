using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace JTS.WindowsCompanion.Relay;

/// <summary>An already enrolled identity. This type does not create keys, pair devices or modify certificate stores.</summary>
public sealed class RelayEndpointIdentity
{
    private readonly object _signingGate = new();
    internal X509Certificate2 Certificate { get; }
    public string DeviceId { get; }

    /// <remarks>The caller owns the certificate and must keep it alive until all connections finish.</remarks>
    public RelayEndpointIdentity(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        if (!certificate.HasPrivateKey) throw new ArgumentException("An enrolled private identity is required.", nameof(certificate));
        Certificate = certificate;
        DeviceId = CertificateDeviceId(certificate);
    }

    internal byte[] Sign(ReadOnlySpan<byte> data)
    {
        lock (_signingGate)
        {
            using var key = Certificate.GetECDsaPrivateKey()
                ?? throw new RelayProtocolException("RELAY_IDENTITY_INVALID");
            return key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
    }

    /// <summary>Proof of possession for one exact enrollment claim; no private material is exported.</summary>
    public byte[] SignEnrollmentTranscript(ReadOnlySpan<byte> transcript)
    {
        if (transcript.Length is < 100 or > 512) throw new RelayProtocolException("ENROLLMENT_TRANSCRIPT_INVALID");
        var fields = System.Text.Encoding.UTF8.GetString(transcript).Split('\n');
        if (fields.Length != 6 || fields[0] != "JTS-PAIR-1" || !Guid.TryParseExact(fields[1], "D", out var id)
            || id == Guid.Empty || id.ToString("D") != fields[1] || fields.Skip(2).Any(f => !RelayWire.IsDeviceId(f)))
            throw new RelayProtocolException("ENROLLMENT_TRANSCRIPT_INVALID");
        return Sign(transcript);
    }

    /// <summary>Signs an exact, durable revocation completion. Does not expose a general signing RPC.</summary>
    public byte[] SignRevocationReceipt(ReadOnlySpan<byte> transcript)
    {
        if (transcript.Length is < 100 or > 512) throw new RelayProtocolException("REVOCATION_TRANSCRIPT_INVALID");
        var f = System.Text.Encoding.UTF8.GetString(transcript).Split('\n');
        if (f.Length != 6 || f[0] != "JTS-PAIR-REVOKED-2" || !Guid.TryParseExact(f[1], "D", out var id)
            || id == Guid.Empty || id.ToString("D") != f[1] || f.Skip(2).Take(3).Any(s => !RelayWire.IsDeviceId(s))
            || f[4] != DeviceId || !long.TryParse(f[5], out var seconds) || seconds is < 1 or > 253402300799)
            throw new RelayProtocolException("REVOCATION_TRANSCRIPT_INVALID");
        return Sign(transcript);
    }

    internal static string CertificateDeviceId(X509Certificate2 certificate)
    {
        using var key = certificate.GetECDsaPublicKey()
            ?? throw new RelayProtocolException("RELAY_IDENTITY_INVALID");
        var parameters = key.ExportParameters(false);
        if (parameters.Curve.Oid.Value != "1.2.840.10045.3.1.7")
            throw new RelayProtocolException("RELAY_IDENTITY_INVALID");
        return RelayWire.Hash(key.ExportSubjectPublicKeyInfo());
    }
}
