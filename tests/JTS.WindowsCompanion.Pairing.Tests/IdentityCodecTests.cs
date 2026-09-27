using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace JTS.WindowsCompanion.Pairing.Tests;

public sealed class IdentityCodecTests
{
    [Theory]
    [InlineData("version")]
    [InlineData("enrollment")]
    [InlineData("certificate-size")]
    [InlineData("certificate-data")]
    [InlineData("private-size")]
    [InlineData("private-data")]
    [InlineData("trailing")]
    [InlineData("truncated")]
    public void AuthenticatedButInvalidClearRecordIsStillRejected(string kind)
    {
        using var fixture = new IdentityFixture();
        using var certificate = RelayIdentityCodec.Generate(fixture.Clock.GetUtcNow());
        var clear = RelayIdentityCodec.Encode(certificate, fixture.EnrollmentId);
        var privateOffset = 21 + BinaryPrimitives.ReadInt32LittleEndian(clear.AsSpan(17));
        switch (kind)
        {
            case "version": clear[0] = 2; break;
            case "enrollment": clear[1] ^= 1; break;
            case "certificate-size": BinaryPrimitives.WriteInt32LittleEndian(clear.AsSpan(17), int.MaxValue); break;
            case "certificate-data": clear[21] ^= 1; break;
            case "private-size": BinaryPrimitives.WriteInt32LittleEndian(clear.AsSpan(privateOffset), 4097); break;
            case "private-data": clear[privateOffset + 4] ^= 1; break;
            case "trailing": clear = ExtendAndErase(clear); break;
            case "truncated": var old = clear; clear = clear[..^1]; CryptographicOperations.ZeroMemory(old); break;
        }
        try { Assert.Throws<RelayIdentityStoreException>(() => RelayIdentityCodec.Decode(clear, fixture.EnrollmentId, null, fixture.Clock.GetUtcNow())); }
        finally { CryptographicOperations.ZeroMemory(clear); }
    }
    [Theory]
    [InlineData("curve")]
    [InlineData("ca")]
    [InlineData("usage")]
    [InlineData("eku")]
    [InlineData("critical")]
    [InlineData("extra")]
    public void WrongCertificateProfileIsRejected(string kind)
    {
        using var fixture = new IdentityFixture();
        using var key = ECDsa.Create(kind == "curve" ? ECCurve.NamedCurves.nistP384 : ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=test only", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(kind == "ca", false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(kind == "usage" ? X509KeyUsageFlags.KeyCertSign : X509KeyUsageFlags.DigitalSignature, kind != "critical"));
        var purposes = new OidCollection { new("1.3.6.1.5.5.7.3.1") };
        if (kind != "eku") purposes.Add(new("1.3.6.1.5.5.7.3.2"));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(purposes, true));
        if (kind == "extra") request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using var certificate = request.CreateSelfSigned(fixture.Clock.GetUtcNow().AddMinutes(-1), fixture.Clock.GetUtcNow().AddHours(1));
        var clear = RelayIdentityCodec.Encode(certificate, fixture.EnrollmentId);
        try { Assert.Throws<RelayIdentityStoreException>(() => RelayIdentityCodec.Decode(clear, fixture.EnrollmentId, null, fixture.Clock.GetUtcNow())); }
        finally { CryptographicOperations.ZeroMemory(clear); }
    }
    [Fact]
    public void PrivateKeyMustMatchCertificateAndHaveNoTrailingBytes()
    {
        using var fixture = new IdentityFixture();
        using var first = RelayIdentityCodec.Generate(fixture.Clock.GetUtcNow());
        using var other = RelayIdentityCodec.Generate(fixture.Clock.GetUtcNow());
        var a = RelayIdentityCodec.Encode(first, fixture.EnrollmentId); var b = RelayIdentityCodec.Encode(other, fixture.EnrollmentId);
        try
        {
            var offset = 21 + BinaryPrimitives.ReadInt32LittleEndian(a.AsSpan(17));
            var otherOffset = 21 + BinaryPrimitives.ReadInt32LittleEndian(b.AsSpan(17));
            Assert.Equal(a.Length - offset, b.Length - otherOffset);
            b.AsSpan(otherOffset).CopyTo(a.AsSpan(offset));
            Assert.Throws<RelayIdentityStoreException>(() => RelayIdentityCodec.Decode(a, fixture.EnrollmentId, null, fixture.Clock.GetUtcNow()));
            var extended = ExtendAndErase(b);
            try
            {
                BinaryPrimitives.WriteInt32LittleEndian(extended.AsSpan(otherOffset), extended.Length - otherOffset - 4);
                Assert.Throws<RelayIdentityStoreException>(() => RelayIdentityCodec.Decode(extended, fixture.EnrollmentId, null, fixture.Clock.GetUtcNow()));
            }
            finally { CryptographicOperations.ZeroMemory(extended); }
        }
        finally { CryptographicOperations.ZeroMemory(a); CryptographicOperations.ZeroMemory(b); }
    }
    private static byte[] ExtendAndErase(byte[] input)
    {
        var result = new byte[input.Length + 1]; input.CopyTo(result, 0); CryptographicOperations.ZeroMemory(input); return result;
    }
}
