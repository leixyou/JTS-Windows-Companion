using System.Security.Cryptography;
using System.Text;
using JTS.WindowsCompanion.Protocol;

namespace JTS.WindowsCompanion.Security;

public sealed record CompanionIdentityMetadata(
    Guid DeviceId,
    string FingerprintSha256,
    string PublicKeyBase64);

public interface ICompanionIdentity
{
    ValueTask<CompanionIdentityMetadata> GetMetadataAsync(CancellationToken cancellationToken);

    ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken);
}

public interface IDataProtector
{
    byte[] Protect(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> entropy);

    byte[] Unprotect(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> entropy);
}

public sealed record PairingProof(
    Guid DeviceId,
    string FingerprintSha256,
    string PublicKeyBase64,
    string ChallengeBase64,
    ulong Sequence,
    long IssuedAtUnixMilliseconds,
    string SignatureBase64);

public static class PairingProofService
{
    private static ReadOnlySpan<byte> Domain => "JTS-WINDOWS-COMPANION-PAIRING-V1\0"u8;

    public static async ValueTask<PairingProof> CreateAsync(
        ICompanionIdentity identity,
        ReadOnlyMemory<byte> challenge,
        ulong sequence,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (challenge.Length is < 16 or > 128)
        {
            throw new CompanionProtocolException("PAIRING_CHALLENGE_INVALID", "The pairing challenge must be 16 to 128 bytes.");
        }

        var metadata = await identity.GetMetadataAsync(cancellationToken).ConfigureAwait(false);
        var signedPayload = BuildSignedPayload(metadata.DeviceId, challenge.Span, sequence, now.ToUnixTimeMilliseconds());
        try
        {
            var signature = await identity.SignAsync(signedPayload, cancellationToken).ConfigureAwait(false);
            return new PairingProof(
                metadata.DeviceId,
                metadata.FingerprintSha256,
                metadata.PublicKeyBase64,
                Convert.ToBase64String(challenge.Span),
                sequence,
                now.ToUnixTimeMilliseconds(),
                Convert.ToBase64String(signature));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signedPayload);
        }
    }

    public static bool Verify(PairingProof proof, TimeSpan maximumAge, DateTimeOffset now)
    {
        byte[] publicKey;
        byte[] challenge;
        byte[] signature;
        try
        {
            publicKey = Convert.FromBase64String(proof.PublicKeyBase64);
            challenge = Convert.FromBase64String(proof.ChallengeBase64);
            signature = Convert.FromBase64String(proof.SignatureBase64);
        }
        catch (FormatException)
        {
            return false;
        }

        if (challenge.Length is < 16 or > 128)
        {
            return false;
        }

        var issuedAt = DateTimeOffset.FromUnixTimeMilliseconds(proof.IssuedAtUnixMilliseconds);
        if (issuedAt > now.AddMinutes(1) || now - issuedAt > maximumAge)
        {
            return false;
        }

        var fingerprint = Convert.ToHexString(SHA256.HashData(publicKey));
        if (!string.Equals(fingerprint, proof.FingerprintSha256, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var signedPayload = BuildSignedPayload(proof.DeviceId, challenge, proof.Sequence, proof.IssuedAtUnixMilliseconds);
        try
        {
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(publicKey, out var bytesRead);
            return bytesRead == publicKey.Length
                && verifier.VerifyData(
                    signedPayload,
                    signature,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signedPayload);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private static byte[] BuildSignedPayload(Guid deviceId, ReadOnlySpan<byte> challenge, ulong sequence, long issuedAt)
    {
        using var stream = new MemoryStream();
        stream.Write(Domain);
        stream.Write(deviceId.ToByteArray());
        stream.Write(BitConverter.GetBytes(sequence));
        stream.Write(BitConverter.GetBytes(issuedAt));
        stream.Write(challenge);
        return stream.ToArray();
    }
}

public sealed class SequenceReplayGuard
{
    private readonly object _sync = new();
    private ulong _lastAccepted;

    public void Accept(ulong sequence)
    {
        lock (_sync)
        {
            if (sequence == 0 || sequence <= _lastAccepted)
            {
                throw new CompanionProtocolException("REPLAY_REJECTED", "The message sequence was already used or is invalid.");
            }

            _lastAccepted = sequence;
        }
    }
}
