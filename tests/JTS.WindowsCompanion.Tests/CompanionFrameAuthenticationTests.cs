using System.Security.Cryptography;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.Tests;

public sealed class CompanionFrameAuthenticationTests
{
    [Fact]
    public void CanonicalFixture_MatchesSwiftByteForByte()
    {
        var windowsDeviceId = Guid.Parse("00112233-4455-6677-8899-aabbccddeeff");
        var clientDeviceId = Guid.Parse("ffeeddcc-bbaa-9988-7766-554433221100");
        var helloChallenge = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
        var authorizationChallenge = Enumerable.Range(32, 32).Select(value => (byte)value).ToArray();

        var binding = CompanionFrameAuthenticator.DeriveSessionBinding(
            windowsDeviceId,
            clientDeviceId,
            helloChallenge,
            authorizationChallenge);
        var canonical = CompanionFrameAuthenticator.BuildCanonicalPayload(
            CompanionProtocol.CurrentVersion,
            CompanionFrameDirection.MacToWindows,
            CompanionFrameType.BinaryChunk,
            CompanionFrameFlags.Final | CompanionFrameFlags.Authenticated,
            0x0102030405060708,
            "fixture"u8,
            binding);

        Assert.Equal(
            "79D5063F1A130AC82991C3AD6D4F4F0CDB03BFEE7805025074FC8AF618C8BB40",
            Convert.ToHexString(binding));
        Assert.Equal(
            "4A54532D434F4D50414E494F4E2D4456432D4652414D452D415554482D56310000010102810001020304050607080000000779D5063F1A130AC82991C3AD6D4F4F0CDB03BFEE7805025074FC8AF618C8BB40F16D05EC6B29248D2C61ADB1E9263F78E4F7BACE1B955014A2D17872CFE4064D",
            Convert.ToHexString(canonical));
    }

    [Fact]
    public async Task PostAuthorizationFrames_AreSignedAndVerifiedInBothDirections()
    {
        using var windowsIdentity = new TestIdentity();
        using var clientIdentity = new TestIdentity();
        var binding = RandomNumberGenerator.GetBytes(SHA256.HashSizeInBytes);
        var windowsContext = Context(binding, clientIdentity);
        var windowsAuthenticator = new CompanionFrameAuthenticator(
            windowsIdentity,
            new FixedContextSource(windowsContext));
        var requestPayload = "{\"request\":true}"u8.ToArray();
        var incoming = SignedFrame(
            clientIdentity,
            CompanionFrameDirection.MacToWindows,
            binding,
            sequence: 7,
            requestPayload);

        var authenticated = windowsAuthenticator.AuthenticateInbound(incoming);
        Assert.Equal(requestPayload, authenticated.Frame.Payload.ToArray());
        Assert.NotNull(authenticated.AuthenticationContext);

        var responsePayload = "{\"response\":true}"u8.ToArray();
        var response = await windowsAuthenticator.ProtectOutboundAsync(
            new CompanionFrame(
                CompanionProtocol.CurrentVersion,
                CompanionFrameType.ControlJson,
                CompanionFrameFlags.Final,
                9,
                responsePayload),
            contextOverride: null,
            CancellationToken.None);

        Assert.True(response.Flags.HasFlag(CompanionFrameFlags.Authenticated));
        Assert.Equal(CompanionProtocol.FrameAuthenticationEnvelopeBytes + responsePayload.Length, response.Payload.Length);
        VerifyEnvelope(
            response,
            windowsIdentity,
            CompanionFrameDirection.WindowsToMac,
            binding);
    }

    [Fact]
    public void UnsignedTamperedReflectedAndOldSessionFrames_FailClosed()
    {
        using var windowsIdentity = new TestIdentity();
        using var clientIdentity = new TestIdentity();
        var binding = RandomNumberGenerator.GetBytes(SHA256.HashSizeInBytes);
        var authenticator = new CompanionFrameAuthenticator(
            windowsIdentity,
            new FixedContextSource(Context(binding, clientIdentity)));
        var unsigned = new CompanionFrame(
            CompanionProtocol.CurrentVersion,
            CompanionFrameType.ControlJson,
            CompanionFrameFlags.Final,
            1,
            "{}"u8.ToArray());
        Assert.Equal(
            "FRAME_AUTH_INVALID",
            Assert.Throws<CompanionProtocolException>(() => authenticator.AuthenticateInbound(unsigned)).Code);

        var valid = SignedFrame(
            clientIdentity,
            CompanionFrameDirection.MacToWindows,
            binding,
            sequence: 2,
            "fixture"u8.ToArray());
        var tamperedBytes = valid.Payload.ToArray();
        tamperedBytes[^1] ^= 0x01;
        var tampered = valid with { Payload = tamperedBytes };
        Assert.Equal(
            "FRAME_AUTH_INVALID",
            Assert.Throws<CompanionProtocolException>(() => authenticator.AuthenticateInbound(tampered)).Code);

        var reflected = SignedFrame(
            clientIdentity,
            CompanionFrameDirection.WindowsToMac,
            binding,
            sequence: 3,
            "fixture"u8.ToArray());
        Assert.Equal(
            "FRAME_AUTH_INVALID",
            Assert.Throws<CompanionProtocolException>(() => authenticator.AuthenticateInbound(reflected)).Code);

        var oldSession = SignedFrame(
            clientIdentity,
            CompanionFrameDirection.MacToWindows,
            RandomNumberGenerator.GetBytes(SHA256.HashSizeInBytes),
            sequence: 4,
            "fixture"u8.ToArray());
        Assert.Equal(
            "FRAME_AUTH_INVALID",
            Assert.Throws<CompanionProtocolException>(() => authenticator.AuthenticateInbound(oldSession)).Code);
    }

    [Fact]
    public async Task AuthenticationEnvelope_IsIncludedInProtocolPayloadLimit()
    {
        using var windowsIdentity = new TestIdentity();
        using var clientIdentity = new TestIdentity();
        var binding = RandomNumberGenerator.GetBytes(SHA256.HashSizeInBytes);
        var authenticator = new CompanionFrameAuthenticator(
            windowsIdentity,
            new FixedContextSource(Context(binding, clientIdentity)));
        var maximumApplicationPayload = new byte[CompanionProtocol.MaxAuthenticatedBinaryPayloadBytes];

        var protectedFrame = await authenticator.ProtectOutboundAsync(
            new CompanionFrame(
                CompanionProtocol.CurrentVersion,
                CompanionFrameType.BinaryChunk,
                CompanionFrameFlags.Final,
                1,
                maximumApplicationPayload),
            contextOverride: null,
            CancellationToken.None);

        Assert.Equal(CompanionProtocol.MaxBinaryPayloadBytes, protectedFrame.Payload.Length);
        var oversized = new CompanionFrame(
            CompanionProtocol.CurrentVersion,
            CompanionFrameType.BinaryChunk,
            CompanionFrameFlags.Final,
            2,
            new byte[CompanionProtocol.MaxAuthenticatedBinaryPayloadBytes + 1]);
        Assert.Equal(
            "FRAME_TOO_LARGE",
            (await Assert.ThrowsAsync<CompanionProtocolException>(async () =>
                await authenticator.ProtectOutboundAsync(
                    oversized,
                    contextOverride: null,
                    CancellationToken.None))).Code);
    }

    private static CompanionFrame SignedFrame(
        TestIdentity signer,
        CompanionFrameDirection direction,
        byte[] binding,
        ulong sequence,
        byte[] payload)
    {
        var flags = CompanionFrameFlags.Final | CompanionFrameFlags.Authenticated;
        var canonical = CompanionFrameAuthenticator.BuildCanonicalPayload(
            CompanionProtocol.CurrentVersion,
            direction,
            CompanionFrameType.ControlJson,
            flags,
            sequence,
            payload,
            binding);
        var signature = signer.Sign(canonical);
        var envelope = new byte[CompanionProtocol.FrameAuthenticationEnvelopeBytes + payload.Length];
        "JTSA"u8.CopyTo(envelope);
        signature.CopyTo(envelope.AsSpan(4));
        payload.CopyTo(envelope.AsSpan(CompanionProtocol.FrameAuthenticationEnvelopeBytes));
        return new CompanionFrame(
            CompanionProtocol.CurrentVersion,
            CompanionFrameType.ControlJson,
            flags,
            sequence,
            envelope);
    }

    private static void VerifyEnvelope(
        CompanionFrame frame,
        TestIdentity signer,
        CompanionFrameDirection direction,
        byte[] binding)
    {
        var payload = frame.Payload[CompanionProtocol.FrameAuthenticationEnvelopeBytes..];
        var canonical = CompanionFrameAuthenticator.BuildCanonicalPayload(
            frame.Version,
            direction,
            frame.Type,
            frame.Flags,
            frame.Sequence,
            payload.Span,
            binding);
        Assert.True(signer.Verify(canonical, frame.Payload.Span.Slice(4, 64)));
    }

    private static CompanionFrameAuthenticationContext Context(byte[] binding, TestIdentity peer)
    {
        var metadata = peer.Metadata;
        return new CompanionFrameAuthenticationContext(
            binding,
            Convert.FromBase64String(metadata.PublicKeyBase64));
    }

    private sealed class FixedContextSource(CompanionFrameAuthenticationContext context)
        : ICompanionFrameAuthenticationContextSource
    {
        public bool TryGetFrameAuthenticationContext(
            out CompanionFrameAuthenticationContext? authenticationContext)
        {
            authenticationContext = context;
            return true;
        }
    }

    private sealed class TestIdentity : ICompanionIdentity, IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public TestIdentity()
        {
            var publicKey = _key.ExportSubjectPublicKeyInfo();
            Metadata = new CompanionIdentityMetadata(
                Guid.NewGuid(),
                Convert.ToHexString(SHA256.HashData(publicKey)),
                Convert.ToBase64String(publicKey));
        }

        public CompanionIdentityMetadata Metadata { get; }

        public ValueTask<CompanionIdentityMetadata> GetMetadataAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(Metadata);

        public ValueTask<byte[]> SignAsync(
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(Sign(payload.Span));

        public byte[] Sign(ReadOnlySpan<byte> payload) => _key.SignData(
            payload,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        public bool Verify(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature) => _key.VerifyData(
            payload,
            signature,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        public void Dispose() => _key.Dispose();
    }
}
