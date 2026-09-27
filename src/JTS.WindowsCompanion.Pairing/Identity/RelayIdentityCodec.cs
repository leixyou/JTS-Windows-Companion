using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using JTS.WindowsCompanion.Relay;

namespace JTS.WindowsCompanion.Pairing;

internal static class RelayIdentityCodec
{
    internal const int MaximumCleartext = 16384, MaximumCiphertext = 32768;
    internal static byte[] Purpose(Guid enrollmentId) => System.Text.Encoding.UTF8.GetBytes($"JTS-ENDPOINT-IDENTITY-V1\n{enrollmentId:D}");

    internal static X509Certificate2 Generate(DateTimeOffset now)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=JTS Terminal device", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.1"), new("1.3.6.1.5.5.7.3.2") }, true));
        return request.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(365));
    }

    internal static byte[] Encode(X509Certificate2 certificate, Guid enrollmentId)
    {
        using var key = certificate.GetECDsaPrivateKey() ?? throw Invalid();
        var privateKey = key.ExportPkcs8PrivateKey();
        using var bytes = new MemoryStream();
        try
        {
            using var writer = new BinaryWriter(bytes, System.Text.Encoding.UTF8, leaveOpen: true);
            writer.Write((byte)1); writer.Write(enrollmentId.ToByteArray());
            var publicCertificate = certificate.RawData;
            writer.Write(publicCertificate.Length); writer.Write(publicCertificate);
            writer.Write(privateKey.Length); writer.Write(privateKey); writer.Flush();
            if (bytes.Length > MaximumCleartext) throw Invalid();
            return bytes.ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(privateKey); CryptographicOperations.ZeroMemory(bytes.GetBuffer()); }
    }

    internal static X509Certificate2 Decode(byte[] clear, Guid enrollmentId, string? expectedDeviceId, DateTimeOffset now)
    {
        byte[]? privateKey = null;
        try
        {
            if (clear.Length is < 26 or > MaximumCleartext) throw Invalid();
            using var bytes = new MemoryStream(clear, writable: false); using var reader = new BinaryReader(bytes);
            if (reader.ReadByte() != 1 || !reader.ReadBytes(16).AsSpan().SequenceEqual(enrollmentId.ToByteArray())) throw Invalid();
            var der = ReadBytes(reader, 8192); privateKey = ReadBytes(reader, 4096);
            if (bytes.Position != bytes.Length) throw Invalid();
            using var certificate = X509CertificateLoader.LoadCertificate(der);
            if (!certificate.RawData.AsSpan().SequenceEqual(der)) throw Invalid();
            ValidateCertificate(certificate, now);
            using var key = ECDsa.Create(); key.ImportPkcs8PrivateKey(privateKey, out var read);
            if (read != privateKey.Length) throw Invalid();
            var attached = certificate.CopyWithPrivateKey(key);
            try
            {
                var identity = new RelayEndpointIdentity(attached);
                if (expectedDeviceId is not null && identity.DeviceId != expectedDeviceId)
                    throw new RelayIdentityStoreException("IDENTITY_DEVICE_MISMATCH");
                if (!OperatingSystem.IsWindows()) return attached;
                // Schannel needs a user-key-store credential. This is an explicit mode, never a fallback.
                var pfx = attached.Export(X509ContentType.Pkcs12);
                try
                {
                    return X509CertificateLoader.LoadPkcs12(pfx, (string?)null, X509KeyStorageFlags.UserKeySet,
                        new Pkcs12LoaderLimits { MaxCertificates = 1, MaxKeys = 1 });
                }
                finally { CryptographicOperations.ZeroMemory(pfx); attached.Dispose(); }
            }
            catch { attached.Dispose(); throw; }
        }
        catch (Exception error) when (error is CryptographicException or ArgumentException or EndOfStreamException or RelayProtocolException)
        { throw Invalid(); }
        finally { if (privateKey is not null) CryptographicOperations.ZeroMemory(privateKey); }
    }

    private static void ValidateCertificate(X509Certificate2 certificate, DateTimeOffset now)
    {
        var extensions = certificate.Extensions.Cast<X509Extension>().ToArray();
        if (certificate.NotBefore.ToUniversalTime() > now.UtcDateTime || certificate.NotAfter.ToUniversalTime() <= now.UtcDateTime)
            throw new RelayIdentityStoreException("IDENTITY_CERTIFICATE_EXPIRED_OR_NOT_YET_VALID");
        if (certificate.SignatureAlgorithm.Value != "1.2.840.10045.4.3.2" || extensions.Length != 3
            || extensions.Select(e => e.Oid?.Value).Distinct().Count() != 3
            || !certificate.IssuerName.RawData.AsSpan().SequenceEqual(certificate.SubjectName.RawData)
            || extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault() is not { CertificateAuthority: false, Critical: true }
            || extensions.OfType<X509KeyUsageExtension>().FirstOrDefault() is not { KeyUsages: X509KeyUsageFlags.DigitalSignature, Critical: true }
            || extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault() is not { Critical: true } usage
            || !usage.EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value).Order().SequenceEqual(new[] { "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2" }))
            throw Invalid();
    }
    private static byte[] ReadBytes(BinaryReader reader, int limit)
    {
        var length = reader.ReadInt32();
        if (length is < 1 || length > limit) throw Invalid();
        var bytes = reader.ReadBytes(length);
        if (bytes.Length != length) { CryptographicOperations.ZeroMemory(bytes); throw Invalid(); }
        return bytes;
    }
    internal static RelayIdentityStoreException Invalid() => new("IDENTITY_STORE_INVALID");
}
