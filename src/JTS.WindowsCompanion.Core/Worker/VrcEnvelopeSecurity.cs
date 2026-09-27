using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.Worker;

public sealed record VrcJobEnvelope(
    string SchemaVersion,
    Guid WindowsDeviceId,
    Guid ClientDeviceId,
    string ClientFingerprintSha256,
    string JobId,
    long TotalBytes,
    string BundleSha256,
    long IssuedAtUnixMilliseconds,
    string SignatureBase64);

public sealed record VrcResultEnvelope(
    string SchemaVersion,
    Guid WindowsDeviceId,
    string WindowsFingerprintSha256,
    Guid ClientDeviceId,
    string ClientFingerprintSha256,
    string JobId,
    string State,
    long TotalBytes,
    string BundleSha256,
    long IssuedAtUnixMilliseconds,
    string SignatureBase64);

public interface IVrcEnvelopeSecurity
{
    ValueTask<VrcJobEnvelope> VerifyJobAsync(
        JsonElement envelope,
        string expectedJobId,
        long expectedTotalBytes,
        string expectedBundleSha256,
        CancellationToken cancellationToken);

    ValueTask<VrcResultEnvelope> SignResultAsync(
        string jobId,
        string state,
        long totalBytes,
        string bundleSha256,
        CancellationToken cancellationToken);
}

/// <summary>
/// Verifies durable Mac-signed job envelopes and creates durable
/// Windows-signed result envelopes. These signatures intentionally bind the
/// paired device identities but not the transient DVC session, so the envelope
/// can be persisted and re-verified after a reconnect.
/// </summary>
public sealed class VrcEnvelopeSecurity : IVrcEnvelopeSecurity
{
    public const string JobSchemaVersion = "jts-vrc-job-envelope-v1";
    public const string ResultSchemaVersion = "jts-vrc-result-envelope-v1";
    public static readonly TimeSpan MaximumEnvelopeAge = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan MaximumFutureSkew = TimeSpan.FromMinutes(1);

    private static readonly HashSet<string> JobProperties = new(StringComparer.Ordinal)
    {
        "schemaVersion",
        "windowsDeviceId",
        "clientDeviceId",
        "clientFingerprintSha256",
        "jobId",
        "totalBytes",
        "bundleSha256",
        "issuedAtUnixMilliseconds",
        "signatureBase64",
    };

    private readonly ICompanionIdentity _windowsIdentity;
    private readonly ICompanionAuthorizedPeerContextSource _peerContextSource;
    private readonly Func<DateTimeOffset> _utcNow;

    public VrcEnvelopeSecurity(
        ICompanionIdentity windowsIdentity,
        ICompanionAuthorizedPeerContextSource peerContextSource,
        Func<DateTimeOffset>? utcNow = null)
    {
        _windowsIdentity = windowsIdentity ?? throw new ArgumentNullException(nameof(windowsIdentity));
        _peerContextSource = peerContextSource ?? throw new ArgumentNullException(nameof(peerContextSource));
        _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
    }

    public async ValueTask<VrcJobEnvelope> VerifyJobAsync(
        JsonElement envelope,
        string expectedJobId,
        long expectedTotalBytes,
        string expectedBundleSha256,
        CancellationToken cancellationToken)
    {
        ValidateExactProperties(envelope, JobProperties, "WORKER_JOB_ENVELOPE_INVALID");
        VrcJobEnvelope job;
        try
        {
            job = envelope.Deserialize<VrcJobEnvelope>(ControlMessageSerializer.Options)
                ?? throw InvalidJobEnvelope();
        }
        catch (JsonException)
        {
            throw InvalidJobEnvelope();
        }

        var expectedDigest = NormalizeSha256(expectedBundleSha256, "WORKER_JOB_ENVELOPE_INVALID");
        if (job.SchemaVersion != JobSchemaVersion
            || job.WindowsDeviceId == Guid.Empty
            || job.ClientDeviceId == Guid.Empty
            || job.JobId != expectedJobId
            || job.TotalBytes != expectedTotalBytes
            || job.TotalBytes <= 0
            || !FixedTimeHexEquals(job.BundleSha256, expectedDigest)
            || !IsSha256(job.ClientFingerprintSha256)
            || !IsFresh(job.IssuedAtUnixMilliseconds, _utcNow()))
        {
            throw InvalidJobEnvelope();
        }

        if (!_peerContextSource.TryGetAuthorizedPeerContext(out var peer) || peer is null)
        {
            throw new CompanionProtocolException(
                "PAIRING_REQUIRED",
                "Client authorization is required for a signed worker job envelope.");
        }

        var windows = await _windowsIdentity.GetMetadataAsync(cancellationToken).ConfigureAwait(false);
        if (job.WindowsDeviceId != windows.DeviceId
            || job.ClientDeviceId != peer.DeviceId
            || !FixedTimeHexEquals(job.ClientFingerprintSha256, peer.FingerprintSha256))
        {
            throw InvalidJobEnvelope();
        }

        byte[] publicKey;
        byte[] signature;
        try
        {
            publicKey = Convert.FromBase64String(peer.PublicKeyBase64);
            signature = Convert.FromBase64String(job.SignatureBase64);
        }
        catch (FormatException)
        {
            throw InvalidJobEnvelope();
        }

        var canonical = VrcEnvelopeCanonicalizer.Job(job with
        {
            BundleSha256 = expectedDigest,
            ClientFingerprintSha256 = NormalizeSha256(
                job.ClientFingerprintSha256,
                "WORKER_JOB_ENVELOPE_INVALID"),
        });
        try
        {
            if (signature.Length != 64
                || !VerifyP256(publicKey, canonical, signature))
            {
                throw InvalidJobEnvelope();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
            CryptographicOperations.ZeroMemory(signature);
            CryptographicOperations.ZeroMemory(canonical);
        }

        return job with
        {
            BundleSha256 = expectedDigest,
            ClientFingerprintSha256 = peer.FingerprintSha256.ToUpperInvariant(),
        };
    }

    public async ValueTask<VrcResultEnvelope> SignResultAsync(
        string jobId,
        string state,
        long totalBytes,
        string bundleSha256,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(jobId)
            || string.IsNullOrEmpty(state)
            || totalBytes <= 0)
        {
            throw new CompanionProtocolException(
                "WORKER_RESULT_ENVELOPE_INVALID",
                "The worker result cannot be signed because its envelope is invalid.");
        }

        if (!_peerContextSource.TryGetAuthorizedPeerContext(out var peer) || peer is null)
        {
            throw new CompanionProtocolException(
                "PAIRING_REQUIRED",
                "Client authorization is required for a signed worker result envelope.");
        }

        var windows = await _windowsIdentity.GetMetadataAsync(cancellationToken).ConfigureAwait(false);
        var unsigned = new VrcResultEnvelope(
            ResultSchemaVersion,
            windows.DeviceId,
            windows.FingerprintSha256.ToUpperInvariant(),
            peer.DeviceId,
            peer.FingerprintSha256.ToUpperInvariant(),
            jobId,
            state,
            totalBytes,
            NormalizeSha256(bundleSha256, "WORKER_RESULT_ENVELOPE_INVALID"),
            _utcNow().ToUnixTimeMilliseconds(),
            SignatureBase64: string.Empty);
        var canonical = VrcEnvelopeCanonicalizer.Result(unsigned);
        try
        {
            var signature = await _windowsIdentity.SignAsync(canonical, cancellationToken).ConfigureAwait(false);
            try
            {
                if (signature.Length != 64)
                {
                    throw new CompanionProtocolException(
                        "WORKER_RESULT_ENVELOPE_INVALID",
                        "The Windows identity returned an invalid result signature.");
                }
                return unsigned with { SignatureBase64 = Convert.ToBase64String(signature) };
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

    private static bool VerifyP256(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> signature)
    {
        try
        {
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(publicKey, out var bytesRead);
            return bytesRead == publicKey.Length
                && verifier.KeySize == 256
                && verifier.VerifyData(
                    payload,
                    signature,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static void ValidateExactProperties(
        JsonElement value,
        IReadOnlySet<string> expected,
        string errorCode)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw new CompanionProtocolException(errorCode, "The signed worker envelope is invalid.");
        }
        var properties = value.EnumerateObject().Select(property => property.Name).ToArray();
        if (properties.Length != expected.Count
            || properties.Any(property => !expected.Contains(property))
            || expected.Any(property => !properties.Contains(property, StringComparer.Ordinal)))
        {
            throw new CompanionProtocolException(errorCode, "The signed worker envelope is invalid.");
        }
    }

    private static bool IsFresh(long issuedAtUnixMilliseconds, DateTimeOffset now)
    {
        DateTimeOffset issuedAt;
        try
        {
            issuedAt = DateTimeOffset.FromUnixTimeMilliseconds(issuedAtUnixMilliseconds);
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
        return issuedAt <= now + MaximumFutureSkew
            && issuedAt >= now - MaximumEnvelopeAge;
    }

    private static bool IsSha256(string? value) => value is { Length: 64 }
        && value.All(char.IsAsciiHexDigit);

    private static string NormalizeSha256(string value, string errorCode)
    {
        if (!IsSha256(value))
        {
            throw new CompanionProtocolException(errorCode, "The signed worker envelope is invalid.");
        }
        return value.ToLowerInvariant();
    }

    private static bool FixedTimeHexEquals(string left, string right)
    {
        if (!IsSha256(left) || !IsSha256(right))
        {
            return false;
        }
        return CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(left),
            Convert.FromHexString(right));
    }

    private static CompanionProtocolException InvalidJobEnvelope() => new(
        "WORKER_JOB_SIGNATURE_INVALID",
        "The worker job envelope signature or identity binding is invalid.");
}

public static class VrcEnvelopeCanonicalizer
{
    private static ReadOnlySpan<byte> JobDomain => "JTS-VRC-JOB-ENVELOPE-V1\0"u8;
    private static ReadOnlySpan<byte> ResultDomain => "JTS-VRC-RESULT-ENVELOPE-V1\0"u8;

    public static byte[] Job(VrcJobEnvelope envelope)
    {
        using var stream = new MemoryStream();
        stream.Write(JobDomain);
        WriteString(stream, envelope.WindowsDeviceId.ToString("D").ToLowerInvariant());
        WriteString(stream, envelope.ClientDeviceId.ToString("D").ToLowerInvariant());
        WriteDigest(stream, envelope.ClientFingerprintSha256);
        WriteString(stream, envelope.JobId);
        WriteInt64(stream, envelope.TotalBytes);
        WriteDigest(stream, envelope.BundleSha256);
        WriteInt64(stream, envelope.IssuedAtUnixMilliseconds);
        return stream.ToArray();
    }

    public static byte[] Result(VrcResultEnvelope envelope)
    {
        using var stream = new MemoryStream();
        stream.Write(ResultDomain);
        WriteString(stream, envelope.WindowsDeviceId.ToString("D").ToLowerInvariant());
        WriteDigest(stream, envelope.WindowsFingerprintSha256);
        WriteString(stream, envelope.ClientDeviceId.ToString("D").ToLowerInvariant());
        WriteDigest(stream, envelope.ClientFingerprintSha256);
        WriteString(stream, envelope.JobId);
        WriteString(stream, envelope.State);
        WriteInt64(stream, envelope.TotalBytes);
        WriteDigest(stream, envelope.BundleSha256);
        WriteInt64(stream, envelope.IssuedAtUnixMilliseconds);
        return stream.ToArray();
    }

    private static void WriteString(Stream stream, string value)
    {
        var encoded = Encoding.UTF8.GetBytes(value);
        try
        {
            if (encoded.Length > ushort.MaxValue)
            {
                throw new CompanionProtocolException(
                    "WORKER_ENVELOPE_INVALID",
                    "A signed worker envelope field is too long.");
            }
            Span<byte> length = stackalloc byte[sizeof(ushort)];
            BinaryPrimitives.WriteUInt16BigEndian(length, checked((ushort)encoded.Length));
            stream.Write(length);
            stream.Write(encoded);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    private static void WriteDigest(Stream stream, string value)
    {
        byte[] digest;
        try
        {
            digest = Convert.FromHexString(value);
        }
        catch (FormatException)
        {
            throw new CompanionProtocolException(
                "WORKER_ENVELOPE_INVALID",
                "A signed worker envelope digest is invalid.");
        }
        try
        {
            if (digest.Length != SHA256.HashSizeInBytes)
            {
                throw new CompanionProtocolException(
                    "WORKER_ENVELOPE_INVALID",
                    "A signed worker envelope digest is invalid.");
            }
            stream.Write(digest);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    private static void WriteInt64(Stream stream, long value)
    {
        Span<byte> encoded = stackalloc byte[sizeof(long)];
        BinaryPrimitives.WriteInt64BigEndian(encoded, value);
        stream.Write(encoded);
    }
}
