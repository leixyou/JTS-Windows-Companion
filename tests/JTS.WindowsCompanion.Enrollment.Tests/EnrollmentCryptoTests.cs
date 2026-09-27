using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace JTS.WindowsCompanion.Enrollment.Tests;

public sealed class EnrollmentCryptoTests
{
    [Fact]
    public void IndependentPythonVectorDecryptsAndAuthenticatesBothDirections()
    {
        using var doc = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures/enrollment.json")));
        var p = doc.RootElement; string S(string name) => p.GetProperty(name).GetString()!;
        using var code = EnrollmentCode.Parse($"jts-pair://enroll?relay={Uri.EscapeDataString(S("relayOrigin"))}&id={S("invitationId")}&key={Convert.ToBase64String(Convert.FromBase64String(S("secretBase64"))).TrimEnd('=').Replace('+', '-').Replace('/', '_')}");
        Assert.Equal(S("claimTokenBase64"), Convert.ToBase64String(code.Derive("relay-claim")));
        Assert.Equal(S("claimTokenHash"), EnrollmentCrypto.Hash(code.Derive("relay-claim")));
        var offer = Convert.FromBase64String(S("offerBase64"));
        Assert.Equal(Convert.FromBase64String(S("offerPlaintextBase64")), EnrollmentCrypto.Decrypt(code, "offer", offer));
        var response = Convert.FromBase64String(S("responseBase64"));
        Assert.Equal(Convert.FromBase64String(S("responsePlaintextBase64")), EnrollmentCrypto.Decrypt(code, "response", response, EnrollmentCrypto.Hash(offer)));
        var transcript = Convert.FromBase64String(S("transcriptBase64"));
        Assert.Equal(S("claimHash"), EnrollmentCrypto.Hash(transcript));
        using var verifier = ECDsa.Create(); verifier.ImportSubjectPublicKeyInfo(Convert.FromBase64String(S("peerSPKIBase64")), out _);
        Assert.True(verifier.VerifyData(transcript, Convert.FromBase64String(S("signatureBase64")), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        using var request = JsonDocument.Parse(Convert.FromBase64String(S("requestBase64")));
        var (bytes, hash, policy) = EnrollmentCrypto.ReadOffer(code, offer, new TestClock(request.RootElement.GetProperty("issuedAtUtc").GetDateTimeOffset().AddSeconds(1)));
        Assert.Equal(S("requestBase64"), Convert.ToBase64String(bytes)); Assert.Equal(EnrollmentCrypto.Hash(bytes), hash); Assert.True(policy.AllowWindows10TLS12);
    }
    [Theory]
    [InlineData("&id=11111111-1111-4111-8111-111111111111")]
    [InlineData("&unknown=value")]
    [InlineData("#fragment")]
    [InlineData("=")]
    public void ExtraCodeFieldsAndTrailingDataAreRejected(string suffix) => Assert.Throws<EnrollmentException>(() => EnrollmentCode.Parse(ValidCode + suffix));
    [Theory]
    [InlineData("http://relay.example.test")]
    [InlineData("https://user@relay.example.test")]
    [InlineData("https://relay.example.test/path")]
    [InlineData("https://relay.example.test?x=1")]
    [InlineData("https://relay.example.test#fragment")]
    [InlineData("https://relay.example.test/")]
    [InlineData("https://relay.example.test:443")]
    [InlineData("https://RELAY.example.test")]
    public void UnsafeRelayOriginsAreRejected(string origin) => Assert.Throws<EnrollmentException>(() => EnrollmentCode.Parse(ValidCode.Replace(Uri.EscapeDataString("https://relay.example.test"), Uri.EscapeDataString(origin))));
    [Fact]
    public void CiphertextCannotMoveAcrossSecretInvitationOrOffer()
    {
        using var code = EnrollmentCode.Parse(ValidCode); var ciphertext = EnrollmentCrypto.Encrypt(code, "response", Encoding.UTF8.GetBytes("private"), new string('a', 64));
        Assert.Throws<EnrollmentException>(() => EnrollmentCrypto.Decrypt(code, "response", ciphertext, new string('b', 64)));
        using var wrong = new EnrollmentCode(code.RelayOrigin, code.InvitationId, RandomNumberGenerator.GetBytes(32));
        Assert.Throws<EnrollmentException>(() => EnrollmentCrypto.Decrypt(wrong, "response", ciphertext, new string('a', 64)));
        using var other = new EnrollmentCode(code.RelayOrigin, Guid.NewGuid(), code.Secret.ToArray());
        Assert.Throws<EnrollmentException>(() => EnrollmentCrypto.Decrypt(other, "response", ciphertext, new string('a', 64)));
        ciphertext[^1] ^= 1;
        Assert.Throws<EnrollmentException>(() => EnrollmentCrypto.Decrypt(code, "response", ciphertext, new string('a', 64)));
    }
    [Fact]
    public void ShortPasswordAndNoncanonicalBase64AreRejected()
    {
        Assert.Throws<EnrollmentException>(() => EnrollmentCode.Parse(ValidCode[..ValidCode.LastIndexOf('=')] + "=123456"));
        Assert.Throws<EnrollmentException>(() => EnrollmentCode.Parse(ValidCode[..^1] + "B"));
    }
    internal const string ValidCode = "jts-pair://enroll?relay=https%3A%2F%2Frelay.example.test&id=11111111-1111-4111-8111-111111111111&key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
}

internal sealed class TestClock(DateTimeOffset now) : TimeProvider
{
    internal DateTimeOffset Now = now;
    public override DateTimeOffset GetUtcNow() => Now;
}
