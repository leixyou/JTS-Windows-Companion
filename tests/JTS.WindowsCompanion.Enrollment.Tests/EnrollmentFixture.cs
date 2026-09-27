using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using JTS.WindowsCompanion.Control;
using JTS.WindowsCompanion.Pairing;
using JTS.WindowsCompanion.Relay;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.Enrollment.Tests;

internal sealed class EnrollmentFixture : IDisposable
{
    internal readonly string DirectoryPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "jts-enrollment-tests-" + Guid.NewGuid().ToString("N"));
    internal readonly TestClock Clock = new(DateTimeOffset.FromUnixTimeSeconds(1_800_000_000));
    private readonly X509Certificate2 _certificate;
    private readonly ECDsa _controller = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly TestProtector _protector = new();
    internal readonly RelayEndpointIdentity Identity;
    internal readonly DurableRelayPairingStore Pairings;
    internal readonly DurableControlGrantStore Grants;
    internal readonly FakeRelay Relay;
    internal readonly string Spki;
    internal readonly string Code = EnrollmentCryptoTests.ValidCode;
    internal RelayDelegatedEnrollment Request { get; }
    internal EnrollmentCoordinator Coordinator;
    internal Action<string>? Checkpoint;
    internal Func<string, Guid, CancellationToken, ValueTask>? Activation;
    internal int ActivationCalls;
    internal readonly FakeRevocationRelay Revocations = new();
    internal Func<string, CancellationToken, ValueTask>? Drain;
    internal int DrainCalls;
    private readonly bool _mailbox;
    internal string Path => System.IO.Path.Combine(DirectoryPath, "enrollment.sealed");
    internal EnrollmentFixture(bool mailbox = false)
    {
        _mailbox = mailbox; Directory.CreateDirectory(DirectoryPath);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _certificate = new CertificateRequest("CN=Enrollment Fixture", key, HashAlgorithmName.SHA256).CreateSelfSigned(Clock.Now.AddDays(-1), Clock.Now.AddYears(2));
        Identity = new(_certificate); Spki = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
        Pairings = DurableRelayPairingStore.CreateNew(System.IO.Path.Combine(DirectoryPath, "pairings.sqlite"), Identity.DeviceId, _protector, clock: Clock);
        Grants = DurableControlGrantStore.CreateNew(System.IO.Path.Combine(DirectoryPath, "grants.sqlite"), _protector, clock: Clock);
        var controllerSpki = _controller.ExportSubjectPublicKeyInfo(); var id = EnrollmentCrypto.Hash(controllerSpki);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new { version = 1, authorizationSource = "ownerDelegated", authorizationReference = "device-ai-control-enabled",
            controllerDeviceID = id, controllerSPKIBase64 = Convert.ToBase64String(controllerSpki), pairingID = Guid.NewGuid(), grantID = Guid.NewGuid(),
            fileGrantID = Guid.NewGuid(), rdpGrantID = Guid.NewGuid(), issuedAtUtc = Clock.Now, expiresAtUtc = Clock.Now.AddMinutes(20), allowWindows10TLS12 = true });
        Request = RelayDelegatedEnrollment.Parse(bytes, Clock);
        using var code = EnrollmentCode.Parse(Code);
        var offer = EnrollmentCrypto.Encrypt(code, "offer", JsonSerializer.SerializeToUtf8Bytes(new { version = 1, relayOrigin = code.RelayOrigin,
            requestBase64 = Convert.ToBase64String(bytes), requestSha256 = EnrollmentCrypto.Hash(bytes) }));
        Relay = new(new(code.InvitationId, id, "pending", Request.ExpiresAtUtc.ToUnixTimeSeconds(), Convert.ToBase64String(offer), null));
        Coordinator = Open();
    }
    private EnrollmentCoordinator Open() => new(Path, "https://relay.example.test", Spki, Identity, _protector, p => { }, Pairings, Grants,
        Pairings.RevokeAsync, Grants.RevokeAsync, ActivateAsync, Relay, Clock, name => Checkpoint?.Invoke(name), _mailbox ? Revocations : null, DrainAsync);
    private ValueTask ActivateAsync(string owner, Guid pairingId, CancellationToken token)
    { ActivationCalls++; return Activation?.Invoke(owner, pairingId, token) ?? ValueTask.CompletedTask; }
    private ValueTask DrainAsync(string owner, CancellationToken token)
    { DrainCalls++; return Drain?.Invoke(owner, token) ?? ValueTask.CompletedTask; }
    internal RevocationRequest RevokeRequest() => Sign(new RevocationRequest(2, Guid.NewGuid().ToString("D"), "https://relay.example.test",
        Request.ControllerDeviceID, Identity.DeviceId, Request.PairingID.ToString("D"), Request.GrantID.ToString("D"),
        Request.FileGrantID.ToString("D"), Request.RdpGrantID.ToString("D"), Clock.Now.ToUnixTimeSeconds(), ""));
    internal RevocationRequest Sign(RevocationRequest request) => request with { SignatureBase64 = Convert.ToBase64String(_controller.SignData(
        request.Transcript(), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) };
    internal void Deliver(RevocationRequest request) => Revocations.Pending.Add(new(request, Request.ControllerSPKIBase64));
    internal void Restart() { Coordinator.Dispose(); Coordinator = Open(); }
    internal void Confirm()
    {
        var r = Relay.Receipt;
        var c = new EnrollmentConfirmation(2, "https://relay.example.test", r.InvitationId.ToString("D"), r.ControllerDeviceId,
            Identity.DeviceId, r.Claim!.ClaimHash, Clock.Now.ToUnixTimeSeconds(), Request.ExpiresAtUtc.ToUnixTimeSeconds(), "");
        c = c with { SignatureBase64 = Convert.ToBase64String(_controller.SignData(c.Transcript(), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) };
        Relay.Receipt = r with { State = "bound", Confirmation = c };
    }
    public void Dispose()
    { Coordinator.Dispose(); Pairings.Dispose(); Grants.Dispose(); _certificate.Dispose(); _controller.Dispose(); _protector.Dispose(); Directory.Delete(DirectoryPath, true); }
}

internal sealed class FakeRelay(EnrollmentReceipt initial) : IEnrollmentRelay
{
    internal EnrollmentReceipt Receipt = initial;
    internal readonly List<EnrollmentClaim> Submitted = [];
    internal bool Offline, LoseClaimResponse;
    public Task<EnrollmentReceipt> ExchangeAsync(string operation, EnrollmentAttempt attempt, string spki, CancellationToken token)
    {
        if (Offline) throw new HttpRequestException();
        if (operation == "claim")
        {
            var claim = new EnrollmentClaim(spki, attempt.ResponseBase64!, attempt.SignatureBase64!, attempt.ClaimHash!);
            Submitted.Add(claim);
            Receipt = Receipt with { State = Receipt.State == "bound" ? "bound" : "claimed", Claim = claim };
            if (LoseClaimResponse) { LoseClaimResponse = false; throw new HttpRequestException(); }
        }
        return Task.FromResult(Receipt);
    }
}

internal sealed class TestProtector : ITaskPayloadProtector, IDisposable
{
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    public byte[] Protect(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> purpose)
    {
        var output = new byte[bytes.Length + 28]; RandomNumberGenerator.Fill(output.AsSpan(0, 12));
        using var aes = new AesGcm(_key, 16); aes.Encrypt(output.AsSpan(0, 12), bytes, output.AsSpan(12, bytes.Length), output.AsSpan(12 + bytes.Length), purpose); return output;
    }
    public byte[] Unprotect(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> purpose)
    {
        var output = new byte[bytes.Length - 28]; using var aes = new AesGcm(_key, 16);
        aes.Decrypt(bytes[..12], bytes.Slice(12, output.Length), bytes[(12 + output.Length)..], output, purpose); return output;
    }
    public void Dispose() => CryptographicOperations.ZeroMemory(_key);
}
