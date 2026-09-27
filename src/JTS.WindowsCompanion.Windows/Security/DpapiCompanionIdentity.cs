using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.Windows.Security;

public sealed class DpapiCompanionIdentity : ICompanionIdentity, IDisposable
{
    private static readonly byte[] Entropy = SHA256.HashData(Encoding.UTF8.GetBytes("JTS.WindowsCompanion.Identity.v1"));
    private readonly string _identityPath;
    private readonly IDataProtector _protector;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private StoredIdentity? _storedIdentity;
    private bool _disposed;

    public DpapiCompanionIdentity(string identityPath, IDataProtector? protector = null)
    {
        if (string.IsNullOrWhiteSpace(identityPath))
        {
            throw new ArgumentException("An identity path is required.", nameof(identityPath));
        }

        _identityPath = Path.GetFullPath(identityPath);
        _protector = protector ?? new DpapiDataProtector();
    }

    public async ValueTask<CompanionIdentityMetadata> GetMetadataAsync(CancellationToken cancellationToken)
    {
        var identity = await GetOrCreateAsync(cancellationToken).ConfigureAwait(false);
        return new CompanionIdentityMetadata(identity.DeviceId, identity.FingerprintSha256, identity.PublicKeyBase64);
    }

    // Enrollment must bind an already observed identity, never create a new key.
    public async ValueTask<CompanionIdentityMetadata> GetExistingMetadataAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var identity = await LoadAsync(cancellationToken).ConfigureAwait(false);
            return new CompanionIdentityMetadata(identity.DeviceId, identity.FingerprintSha256, identity.PublicKeyBase64);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        var identity = await GetOrCreateAsync(cancellationToken).ConfigureAwait(false);
        var protectedPrivateKey = Convert.FromBase64String(identity.ProtectedPrivateKeyBase64);
        var privateKey = _protector.Unprotect(protectedPrivateKey, Entropy);
        try
        {
            using var signer = ECDsa.Create();
            signer.ImportPkcs8PrivateKey(privateKey, out var bytesRead);
            if (bytesRead != privateKey.Length)
            {
                throw new CryptographicException("The companion identity contains trailing private-key data.");
            }

            return signer.SignData(
                payload.Span,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
            CryptographicOperations.ZeroMemory(protectedPrivateKey);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _gate.Dispose();
        _disposed = true;
    }

    private async ValueTask<StoredIdentity> GetOrCreateAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_storedIdentity is not null)
        {
            return _storedIdentity;
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_storedIdentity is not null)
            {
                return _storedIdentity;
            }

            _storedIdentity = File.Exists(_identityPath)
                ? await LoadAsync(cancellationToken).ConfigureAwait(false)
                : await CreateAsync(cancellationToken).ConfigureAwait(false);
            return _storedIdentity;
        }
        finally
        {
            _gate.Release();
        }
    }

    private async ValueTask<StoredIdentity> LoadAsync(CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            _identityPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            4096,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var identity = await JsonSerializer.DeserializeAsync<StoredIdentity>(stream, cancellationToken: cancellationToken).ConfigureAwait(false)
            ?? throw new CryptographicException("The companion identity file is empty.");
        Validate(identity);
        return identity;
    }

    private async ValueTask<StoredIdentity> CreateAsync(CancellationToken cancellationToken)
    {
        using var identityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = identityKey.ExportPkcs8PrivateKey();
        var publicKey = identityKey.ExportSubjectPublicKeyInfo();
        var protectedPrivateKey = _protector.Protect(privateKey, Entropy);
        try
        {
            var identity = new StoredIdentity(
                Guid.NewGuid(),
                Convert.ToHexString(SHA256.HashData(publicKey)),
                Convert.ToBase64String(publicKey),
                Convert.ToBase64String(protectedPrivateKey));
            var parent = Path.GetDirectoryName(_identityPath)
                ?? throw new InvalidOperationException("The companion identity path has no parent directory.");
            Directory.CreateDirectory(parent);
            var temporaryPath = _identityPath + $".{Guid.NewGuid():N}.tmp";
            try
            {
                await File.WriteAllTextAsync(
                    temporaryPath,
                    JsonSerializer.Serialize(identity),
                    Encoding.UTF8,
                    cancellationToken).ConfigureAwait(false);
                File.Move(temporaryPath, _identityPath, overwrite: false);
            }
            finally
            {
                if (File.Exists(temporaryPath))
                {
                    File.Delete(temporaryPath);
                }
            }

            return identity;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
            CryptographicOperations.ZeroMemory(protectedPrivateKey);
        }
    }

    private void Validate(StoredIdentity identity)
    {
        if (identity.DeviceId == Guid.Empty || identity.FingerprintSha256.Length != 64)
        {
            throw new CryptographicException("The companion identity metadata is invalid.");
        }

        var publicKey = Convert.FromBase64String(identity.PublicKeyBase64);
        var protectedPrivateKey = Convert.FromBase64String(identity.ProtectedPrivateKeyBase64);
        var privateKey = _protector.Unprotect(protectedPrivateKey, Entropy);
        try
        {
            var fingerprint = Convert.ToHexString(SHA256.HashData(publicKey));
            if (!string.Equals(fingerprint, identity.FingerprintSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new CryptographicException("The companion identity fingerprint is invalid.");
            }

            using var signer = ECDsa.Create();
            signer.ImportPkcs8PrivateKey(privateKey, out var bytesRead);
            var derivedPublicKey = signer.ExportSubjectPublicKeyInfo();
            if (bytesRead != privateKey.Length
                || !CryptographicOperations.FixedTimeEquals(derivedPublicKey, publicKey))
            {
                throw new CryptographicException("The companion identity key pair is invalid.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
            CryptographicOperations.ZeroMemory(protectedPrivateKey);
            CryptographicOperations.ZeroMemory(privateKey);
        }
    }

    private sealed record StoredIdentity(
        Guid DeviceId,
        string FingerprintSha256,
        string PublicKeyBase64,
        string ProtectedPrivateKeyBase64);
}
