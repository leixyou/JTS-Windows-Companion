using System.Buffers.Binary;
using System.Security.Cryptography;
using JTS.WindowsCompanion.Protocol;

namespace JTS.WindowsCompanion.Security;

public enum CompanionFrameDirection : byte
{
    MacToWindows = 1,
    WindowsToMac = 2,
}

public interface ICompanionFrameAuthenticationContextSource
{
    bool TryGetFrameAuthenticationContext(out CompanionFrameAuthenticationContext? context);
}

public sealed class CompanionFrameAuthenticationContext
{
    private static ReadOnlySpan<byte> OperationOwnerDomain =>
        "JTS-COMPANION-OPERATION-OWNER-V1\0"u8;

    private readonly byte[] _sessionBinding;
    private readonly byte[] _peerPublicKey;

    public CompanionFrameAuthenticationContext(
        ReadOnlySpan<byte> sessionBinding,
        ReadOnlySpan<byte> peerPublicKey)
    {
        if (sessionBinding.Length != SHA256.HashSizeInBytes || peerPublicKey.IsEmpty)
        {
            throw new CompanionProtocolException(
                "FRAME_AUTH_CONTEXT_INVALID",
                "The frame authentication context is invalid.");
        }

        _sessionBinding = sessionBinding.ToArray();
        _peerPublicKey = peerPublicKey.ToArray();
        ValidatePeerPublicKey(_peerPublicKey);
    }

    internal ReadOnlySpan<byte> SessionBinding => _sessionBinding;

    internal ReadOnlySpan<byte> PeerPublicKey => _peerPublicKey;

    internal string DeriveOperationOwnerKey()
    {
        var material = GC.AllocateUninitializedArray<byte>(
            OperationOwnerDomain.Length + _sessionBinding.Length + _peerPublicKey.Length);
        var digest = new byte[SHA256.HashSizeInBytes];
        try
        {
            OperationOwnerDomain.CopyTo(material);
            _sessionBinding.CopyTo(material.AsSpan(OperationOwnerDomain.Length));
            _peerPublicKey.CopyTo(material.AsSpan(OperationOwnerDomain.Length + _sessionBinding.Length));
            SHA256.HashData(material, digest);
            return Convert.ToHexString(digest);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(material);
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    public CompanionFrameAuthenticationContext Copy() => new(_sessionBinding, _peerPublicKey);

    private static void ValidatePeerPublicKey(ReadOnlySpan<byte> publicKey)
    {
        try
        {
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(publicKey, out var bytesRead);
            if (bytesRead != publicKey.Length || verifier.KeySize != 256)
            {
                throw new CryptographicException();
            }
        }
        catch (CryptographicException)
        {
            throw new CompanionProtocolException(
                "FRAME_AUTH_CONTEXT_INVALID",
                "The frame authentication peer key is invalid.");
        }
    }
}

public sealed record AuthenticatedCompanionFrame(
    CompanionFrame Frame,
    CompanionFrameAuthenticationContext? AuthenticationContext);

/// Adds and verifies a fixed `JTSA || P1363(r||s)` envelope around the
/// application payload while leaving the existing 24-byte DVC header stable.
public sealed class CompanionFrameAuthenticator
{
    private static ReadOnlySpan<byte> EnvelopeMagic => "JTSA"u8;
    private static ReadOnlySpan<byte> FrameDomain => "JTS-COMPANION-DVC-FRAME-AUTH-V1\0"u8;
    private static ReadOnlySpan<byte> SessionDomain => "JTS-COMPANION-DVC-SESSION-V1\0"u8;

    private readonly ICompanionIdentity _localIdentity;
    private readonly ICompanionFrameAuthenticationContextSource _contextSource;

    public CompanionFrameAuthenticator(
        ICompanionIdentity localIdentity,
        ICompanionFrameAuthenticationContextSource contextSource)
    {
        _localIdentity = localIdentity ?? throw new ArgumentNullException(nameof(localIdentity));
        _contextSource = contextSource ?? throw new ArgumentNullException(nameof(contextSource));
    }

    public AuthenticatedCompanionFrame AuthenticateInbound(CompanionFrame frame)
    {
        ArgumentNullException.ThrowIfNull(frame);
        if (!_contextSource.TryGetFrameAuthenticationContext(out var context) || context is null)
        {
            if (frame.Flags.HasFlag(CompanionFrameFlags.Authenticated))
            {
                throw InvalidAuthentication("No authorized frame authentication session is active.");
            }

            return new AuthenticatedCompanionFrame(frame, null);
        }

        return new AuthenticatedCompanionFrame(
            VerifyAndUnwrap(frame, CompanionFrameDirection.MacToWindows, context),
            context);
    }

    public async ValueTask<CompanionFrame> ProtectOutboundAsync(
        CompanionFrame frame,
        CompanionFrameAuthenticationContext? contextOverride,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(frame);
        var context = contextOverride;
        if (context is null)
        {
            _contextSource.TryGetFrameAuthenticationContext(out context);
        }

        if (context is null)
        {
            if (frame.Flags.HasFlag(CompanionFrameFlags.Authenticated))
            {
                throw InvalidAuthentication("An authenticated frame has no active session context.");
            }

            return frame;
        }

        ValidateApplicationPayloadLength(frame.Type, frame.Payload.Length);
        var authenticatedFlags = frame.Flags | CompanionFrameFlags.Authenticated;
        var canonical = BuildCanonicalPayload(
            frame.Version,
            CompanionFrameDirection.WindowsToMac,
            frame.Type,
            authenticatedFlags,
            frame.Sequence,
            frame.Payload.Span,
            context.SessionBinding);
        try
        {
            var signature = await _localIdentity.SignAsync(canonical, cancellationToken).ConfigureAwait(false);
            try
            {
                if (signature.Length != 64)
                {
                    throw InvalidAuthentication("The local P-256 identity returned an invalid signature.");
                }

                var envelope = GC.AllocateUninitializedArray<byte>(
                    CompanionProtocol.FrameAuthenticationEnvelopeBytes + frame.Payload.Length);
                EnvelopeMagic.CopyTo(envelope);
                signature.CopyTo(envelope.AsSpan(EnvelopeMagic.Length, 64));
                frame.Payload.Span.CopyTo(envelope.AsSpan(CompanionProtocol.FrameAuthenticationEnvelopeBytes));
                return frame with
                {
                    Flags = authenticatedFlags,
                    Payload = envelope,
                };
            }
            finally
            {
                CryptographicOperations.ZeroMemory(signature);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    public static byte[] DeriveSessionBinding(
        Guid windowsDeviceId,
        Guid clientDeviceId,
        ReadOnlySpan<byte> helloChallenge,
        ReadOnlySpan<byte> authorizationChallenge)
    {
        if (windowsDeviceId == Guid.Empty
            || clientDeviceId == Guid.Empty
            || helloChallenge.Length != 32
            || authorizationChallenge.Length != CompanionAuthorizationSession.ChallengeBytes)
        {
            throw new CompanionProtocolException(
                "FRAME_AUTH_CONTEXT_INVALID",
                "The frame authentication session binding inputs are invalid.");
        }

        var material = GC.AllocateUninitializedArray<byte>(
            SessionDomain.Length + 16 + 16 + helloChallenge.Length + authorizationChallenge.Length);
        var offset = 0;
        SessionDomain.CopyTo(material);
        offset += SessionDomain.Length;
        windowsDeviceId.TryWriteBytes(material.AsSpan(offset, 16));
        offset += 16;
        clientDeviceId.TryWriteBytes(material.AsSpan(offset, 16));
        offset += 16;
        helloChallenge.CopyTo(material.AsSpan(offset));
        offset += helloChallenge.Length;
        authorizationChallenge.CopyTo(material.AsSpan(offset));
        try
        {
            return SHA256.HashData(material);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(material);
        }
    }

    public static byte[] BuildCanonicalPayload(
        ushort protocolVersion,
        CompanionFrameDirection direction,
        CompanionFrameType frameType,
        CompanionFrameFlags flags,
        ulong sequence,
        ReadOnlySpan<byte> applicationPayload,
        ReadOnlySpan<byte> sessionBinding)
    {
        if (!Enum.IsDefined(direction)
            || !Enum.IsDefined(frameType)
            || sequence == 0
            || applicationPayload.Length > int.MaxValue
            || sessionBinding.Length != SHA256.HashSizeInBytes)
        {
            throw InvalidAuthentication("The canonical frame authentication inputs are invalid.");
        }

        var canonical = GC.AllocateUninitializedArray<byte>(
            FrameDomain.Length + 2 + 1 + 1 + 1 + 1 + 8 + 4 + SHA256.HashSizeInBytes + SHA256.HashSizeInBytes);
        var offset = 0;
        FrameDomain.CopyTo(canonical);
        offset += FrameDomain.Length;
        BinaryPrimitives.WriteUInt16BigEndian(canonical.AsSpan(offset, 2), protocolVersion);
        offset += 2;
        canonical[offset++] = (byte)direction;
        canonical[offset++] = (byte)frameType;
        canonical[offset++] = (byte)flags;
        canonical[offset++] = 0;
        BinaryPrimitives.WriteUInt64BigEndian(canonical.AsSpan(offset, 8), sequence);
        offset += 8;
        BinaryPrimitives.WriteUInt32BigEndian(canonical.AsSpan(offset, 4), checked((uint)applicationPayload.Length));
        offset += 4;
        sessionBinding.CopyTo(canonical.AsSpan(offset, SHA256.HashSizeInBytes));
        offset += SHA256.HashSizeInBytes;
        SHA256.HashData(applicationPayload, canonical.AsSpan(offset, SHA256.HashSizeInBytes));
        return canonical;
    }

    private static CompanionFrame VerifyAndUnwrap(
        CompanionFrame frame,
        CompanionFrameDirection direction,
        CompanionFrameAuthenticationContext context)
    {
        if (!frame.Flags.HasFlag(CompanionFrameFlags.Authenticated)
            || frame.Payload.Length < CompanionProtocol.FrameAuthenticationEnvelopeBytes
            || !frame.Payload.Span[..EnvelopeMagic.Length].SequenceEqual(EnvelopeMagic))
        {
            throw InvalidAuthentication("The frame signature envelope is missing or malformed.");
        }

        var signature = frame.Payload.Span.Slice(EnvelopeMagic.Length, 64);
        var applicationPayload = frame.Payload[CompanionProtocol.FrameAuthenticationEnvelopeBytes..];
        ValidateApplicationPayloadLength(frame.Type, applicationPayload.Length);
        var canonical = BuildCanonicalPayload(
            frame.Version,
            direction,
            frame.Type,
            frame.Flags,
            frame.Sequence,
            applicationPayload.Span,
            context.SessionBinding);
        try
        {
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(context.PeerPublicKey, out var bytesRead);
            if (bytesRead != context.PeerPublicKey.Length
                || verifier.KeySize != 256
                || !verifier.VerifyData(
                    canonical,
                    signature,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                throw InvalidAuthentication("The frame signature is invalid.");
            }
        }
        catch (CryptographicException)
        {
            throw InvalidAuthentication("The frame signature is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }

        return frame with { Payload = applicationPayload };
    }

    private static void ValidateApplicationPayloadLength(CompanionFrameType type, int length)
    {
        var maximum = type == CompanionFrameType.BinaryChunk
            ? CompanionProtocol.MaxAuthenticatedBinaryPayloadBytes
            : CompanionProtocol.MaxAuthenticatedControlPayloadBytes;
        if (length < 0 || length > maximum)
        {
            throw new CompanionProtocolException(
                "FRAME_TOO_LARGE",
                "The authenticated application payload is outside the allowed size.");
        }
    }

    private static CompanionProtocolException InvalidAuthentication(string message) =>
        new("FRAME_AUTH_INVALID", message);
}
