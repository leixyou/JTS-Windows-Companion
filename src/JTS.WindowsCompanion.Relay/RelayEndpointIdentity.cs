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
