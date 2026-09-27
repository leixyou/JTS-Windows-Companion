using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using JTS.WindowsCompanion.Relay;

namespace JTS.WindowsCompanion.Pairing;

/// <summary>Owns one loaded identity and its exclusive disk lease. Drain all clients before disposing.</summary>
public sealed class StoredRelayIdentity : IDisposable
{
    private readonly X509Certificate2 _certificate;
    private readonly FileStream _lease;
    private readonly RelayEndpointIdentity _identity;
    private int _disposed;
    public RelayIdentityDescription Description { get; }
    public RelayEndpointIdentity Identity
    {
        get { ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this); return _identity; }
    }
    internal StoredRelayIdentity(X509Certificate2 certificate, FileStream lease)
    {
        _certificate = certificate; _lease = lease; _identity = new(certificate);
        using var key = certificate.GetECDsaPublicKey()!;
        Description = new(_identity.DeviceId, Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),
            Convert.ToBase64String(certificate.RawData), new DateTimeOffset(certificate.NotAfter.ToUniversalTime()));
    }
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _certificate.Dispose(); _lease.Dispose();
    }
    public override string ToString() => "StoredRelayIdentity (private material omitted)";
}

/// <summary>Public enrollment data only; exporting it does not pair or authorize a device.</summary>
public sealed record RelayIdentityDescription(string DeviceId, string PublicKeySpkiBase64,
    string CertificateDerBase64, DateTimeOffset CertificateExpiresAt);

public sealed class RelayIdentityStoreException(string code) : IOException(code)
{
    public string Code { get; } = code;
}
