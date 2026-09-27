using System.Buffers.Binary;
using System.Security.Cryptography;
using JTS.WindowsCompanion.Protocol;

namespace JTS.WindowsCompanion.Security;

public sealed record CompanionPeerIdentity(
    Guid DeviceId,
    string FingerprintSha256,
    string PublicKeyBase64);

public sealed record CompanionPeerGrant(
    CompanionPeerIdentity Identity,
    DateTimeOffset ApprovedAtUtc,
    CompanionDelegatedConsentReceipt? ConsentReceipt = null);

public interface ICompanionPeerStore
{
    ValueTask<CompanionPeerGrant?> LoadAsync(CancellationToken cancellationToken);

    ValueTask SaveIfAbsentAsync(CompanionPeerGrant grant, CancellationToken cancellationToken);

    ValueTask ClearAsync(CancellationToken cancellationToken);
}

public interface ICompanionPairingConsentPrompt
{
    ValueTask<bool> ConfirmAsync(CompanionPeerIdentity peer, CancellationToken cancellationToken);
}

public sealed record ClientAuthorizationProof(
    Guid DeviceId,
    string FingerprintSha256,
    string PublicKeyBase64,
    string ChallengeBase64,
    ulong Sequence,
    long IssuedAtUnixMilliseconds,
    string SignatureBase64);

public static class ClientAuthorizationProofService
{
    private static ReadOnlySpan<byte> Domain => "JTS-MAC-COMPANION-AUTHORIZATION-V1\0"u8;

    public static async ValueTask<ClientAuthorizationProof> CreateAsync(
        ICompanionIdentity clientIdentity,
        Guid windowsDeviceId,
        ReadOnlyMemory<byte> challenge,
        ulong sequence,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(clientIdentity);
        ValidateChallengeAndSequence(windowsDeviceId, challenge.Span, sequence);
        var metadata = await clientIdentity.GetMetadataAsync(cancellationToken).ConfigureAwait(false);
        var peer = CompanionPeerIdentityValidation.Normalize(new CompanionPeerIdentity(
            metadata.DeviceId,
            metadata.FingerprintSha256,
            metadata.PublicKeyBase64));
        var issuedAt = now.ToUnixTimeMilliseconds();
        var signedPayload = BuildSignedPayload(
            windowsDeviceId,
            peer.DeviceId,
            challenge.Span,
            sequence,
            issuedAt);
        try
        {
            var signature = await clientIdentity.SignAsync(signedPayload, cancellationToken).ConfigureAwait(false);
            try
            {
                return new ClientAuthorizationProof(
                    peer.DeviceId,
                    peer.FingerprintSha256,
                    peer.PublicKeyBase64,
                    Convert.ToBase64String(challenge.Span),
                    sequence,
                    issuedAt,
                    Convert.ToBase64String(signature));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(signature);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signedPayload);
        }
    }

    public static CompanionPeerIdentity Validate(
        ClientAuthorizationProof proof,
        Guid windowsDeviceId,
        ReadOnlySpan<byte> expectedChallenge,
        TimeSpan maximumAge,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(proof);
        if (maximumAge <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumAge));
        }

        ValidateChallengeAndSequence(windowsDeviceId, expectedChallenge, proof.Sequence);
        var peer = CompanionPeerIdentityValidation.Normalize(new CompanionPeerIdentity(
            proof.DeviceId,
            proof.FingerprintSha256,
            proof.PublicKeyBase64));
        byte[] challenge;
        byte[] signature;
        try
        {
            if (string.IsNullOrWhiteSpace(proof.ChallengeBase64)
                || string.IsNullOrWhiteSpace(proof.SignatureBase64)
                || proof.ChallengeBase64.Length > 256
                || proof.SignatureBase64.Length > 1_024)
            {
                throw new FormatException();
            }

            challenge = Convert.FromBase64String(proof.ChallengeBase64);
            signature = Convert.FromBase64String(proof.SignatureBase64);
        }
        catch (FormatException)
        {
            throw new CompanionProtocolException(
                "CLIENT_PROOF_INVALID",
                "The client authorization proof is invalid.");
        }

        try
        {
            if (challenge.Length != expectedChallenge.Length
                || !CryptographicOperations.FixedTimeEquals(challenge, expectedChallenge))
            {
                throw new CompanionProtocolException(
                    "PAIRING_CHALLENGE_MISMATCH",
                    "The client authorization challenge does not match this session.");
            }

            DateTimeOffset issuedAt;
            try
            {
                issuedAt = DateTimeOffset.FromUnixTimeMilliseconds(proof.IssuedAtUnixMilliseconds);
            }
            catch (ArgumentOutOfRangeException)
            {
                throw new CompanionProtocolException(
                    "PAIRING_PROOF_EXPIRED",
                    "The client authorization proof is outside the allowed time window.");
            }

            if (issuedAt > now.AddMinutes(1) || now - issuedAt > maximumAge)
            {
                throw new CompanionProtocolException(
                    "PAIRING_PROOF_EXPIRED",
                    "The client authorization proof is outside the allowed time window.");
            }

            var signedPayload = BuildSignedPayload(
                windowsDeviceId,
                peer.DeviceId,
                challenge,
                proof.Sequence,
                proof.IssuedAtUnixMilliseconds);
            try
            {
                var publicKey = Convert.FromBase64String(peer.PublicKeyBase64);
                try
                {
                    using var verifier = ECDsa.Create();
                    verifier.ImportSubjectPublicKeyInfo(publicKey, out var bytesRead);
                    if (bytesRead != publicKey.Length
                        || verifier.KeySize != 256
                        || !verifier.VerifyData(
                            signedPayload,
                            signature,
                            HashAlgorithmName.SHA256,
                            DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                    {
                        throw new CompanionProtocolException(
                            "PAIRING_SIGNATURE_INVALID",
                            "The client authorization signature is invalid.");
                    }
                }
                catch (CryptographicException)
                {
                    throw new CompanionProtocolException(
                        "PAIRING_SIGNATURE_INVALID",
                        "The client authorization signature is invalid.");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(publicKey);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(signedPayload);
            }

            return peer;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private static void ValidateChallengeAndSequence(
        Guid windowsDeviceId,
        ReadOnlySpan<byte> challenge,
        ulong sequence)
    {
        if (windowsDeviceId == Guid.Empty
            || challenge.Length != CompanionAuthorizationSession.ChallengeBytes
            || sequence == 0)
        {
            throw new CompanionProtocolException(
                "CLIENT_PROOF_INVALID",
                "The client authorization proof is invalid.");
        }
    }

    private static byte[] BuildSignedPayload(
        Guid windowsDeviceId,
        Guid clientDeviceId,
        ReadOnlySpan<byte> challenge,
        ulong sequence,
        long issuedAt)
    {
        using var stream = new MemoryStream();
        stream.Write(Domain);
        stream.Write(windowsDeviceId.ToByteArray());
        stream.Write(clientDeviceId.ToByteArray());
        Span<byte> integer = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64LittleEndian(integer, sequence);
        stream.Write(integer);
        BinaryPrimitives.WriteInt64LittleEndian(integer, issuedAt);
        stream.Write(integer);
        stream.Write(challenge);
        return stream.ToArray();
    }
}

public static class CompanionPeerIdentityValidation
{
    public static CompanionPeerIdentity Normalize(CompanionPeerIdentity peer)
    {
        ArgumentNullException.ThrowIfNull(peer);
        if (peer.DeviceId == Guid.Empty
            || string.IsNullOrWhiteSpace(peer.FingerprintSha256)
            || string.IsNullOrWhiteSpace(peer.PublicKeyBase64)
            || peer.FingerprintSha256.Length != 64
            || !peer.FingerprintSha256.All(Uri.IsHexDigit)
            || peer.PublicKeyBase64.Length is < 1 or > 1_024)
        {
            throw new CompanionProtocolException(
                "CLIENT_IDENTITY_INVALID",
                "The client identity is invalid.");
        }

        byte[] publicKey;
        try
        {
            publicKey = Convert.FromBase64String(peer.PublicKeyBase64);
        }
        catch (FormatException)
        {
            throw new CompanionProtocolException(
                "CLIENT_IDENTITY_INVALID",
                "The client identity is invalid.");
        }

        try
        {
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(publicKey, out var bytesRead);
            var fingerprint = Convert.ToHexString(SHA256.HashData(publicKey));
            if (bytesRead != publicKey.Length
                || verifier.KeySize != 256
                || !string.Equals(fingerprint, peer.FingerprintSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new CompanionProtocolException(
                    "CLIENT_IDENTITY_INVALID",
                    "The client identity is invalid.");
            }

            return peer with
            {
                FingerprintSha256 = fingerprint,
                PublicKeyBase64 = Convert.ToBase64String(publicKey),
            };
        }
        catch (CryptographicException)
        {
            throw new CompanionProtocolException(
                "CLIENT_IDENTITY_INVALID",
                "The client identity is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    public static bool Matches(CompanionPeerIdentity first, CompanionPeerIdentity second)
    {
        var normalizedFirst = Normalize(first);
        var normalizedSecond = Normalize(second);
        var firstKey = Convert.FromBase64String(normalizedFirst.PublicKeyBase64);
        var secondKey = Convert.FromBase64String(normalizedSecond.PublicKeyBase64);
        try
        {
            return normalizedFirst.DeviceId == normalizedSecond.DeviceId
                && string.Equals(
                    normalizedFirst.FingerprintSha256,
                    normalizedSecond.FingerprintSha256,
                    StringComparison.Ordinal)
                && CryptographicOperations.FixedTimeEquals(firstKey, secondKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(firstKey);
            CryptographicOperations.ZeroMemory(secondKey);
        }
    }
}
