using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Control;
using JTS.WindowsCompanion.Pairing;
using JTS.WindowsCompanion.Relay;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.Enrollment;

public sealed record EnrollmentManagementStatus(string State, string DeviceId, string RelayOrigin, Guid? InvitationId, string? ErrorCode);

/// <summary>Authority-owned durable enrollment. Network claims never mutate trust before a bound receipt.</summary>
public sealed partial class EnrollmentCoordinator : IDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly EnrollmentAttemptStore _store;
    private readonly DurableRelayPairingStore _pairings;
    private readonly DurableControlGrantStore _grants;
    private readonly IEnrollmentRelay _relay;
    private readonly RelayEndpointIdentity _identity;
    private readonly string _spki, _origin;
    private readonly TimeProvider _clock;
    private readonly Func<string, Guid, CancellationToken, ValueTask> _revokePairing;
    private readonly Func<string, Guid, CancellationToken, ValueTask> _revokeGrant;
    private readonly Func<string, Guid, CancellationToken, ValueTask> _activatePairing;
    private readonly Action<string>? _checkpoint;
    public EnrollmentCoordinator(string path, string relayOrigin, string spki, RelayEndpointIdentity identity, ITaskPayloadProtector protector,
        Action<string> checkPath, DurableRelayPairingStore pairings, DurableControlGrantStore grants,
        Func<string, Guid, CancellationToken, ValueTask> revokePairing, Func<string, Guid, CancellationToken, ValueTask> revokeGrant,
        Func<string, Guid, CancellationToken, ValueTask> activatePairing,
        RelayControlClient? managementRelay = null, Func<string, CancellationToken, ValueTask>? drainPeer = null)
        : this(path, relayOrigin, spki, identity, protector, checkPath, pairings, grants, revokePairing, revokeGrant, activatePairing,
            new EnrollmentRelayClient(new Uri(relayOrigin)), TimeProvider.System, null,
            managementRelay is null ? null : new RevocationRelayClient(managementRelay), drainPeer) { }
    internal EnrollmentCoordinator(string path, string relayOrigin, string spki, RelayEndpointIdentity identity, ITaskPayloadProtector protector,
        Action<string> checkPath, DurableRelayPairingStore pairings, DurableControlGrantStore grants,
        Func<string, Guid, CancellationToken, ValueTask> revokePairing, Func<string, Guid, CancellationToken, ValueTask> revokeGrant,
        Func<string, Guid, CancellationToken, ValueTask> activatePairing,
        IEnrollmentRelay relay, TimeProvider clock, Action<string>? checkpoint = null,
        IRevocationRelay? revocations = null, Func<string, CancellationToken, ValueTask>? drainPeer = null)
    {
        _origin = EnrollmentCode.CanonicalOrigin(relayOrigin); _spki = spki; _identity = identity;
        if (EnrollmentCrypto.Hash(EnrollmentCrypto.Base64(spki, 512)) != identity.DeviceId || pairings.LocalDeviceId != identity.DeviceId)
            throw new EnrollmentException("ENROLLMENT_IDENTITY_MISMATCH");
        _store = new(path, identity.DeviceId, protector, checkPath); _pairings = pairings; _grants = grants; _relay = relay; _clock = clock;
        _revokePairing = revokePairing; _revokeGrant = revokeGrant; _activatePairing = activatePairing; _checkpoint = checkpoint; _drainPeer = drainPeer;
        if (revocations is not null)
        {
            try
            {
                if (drainPeer is null) throw new ArgumentException("Revocation completion requires an executor drain callback.");
                _revocations = new(path + ".revocations", _origin, identity, protector, checkPath, revocations, clock, ApplyRemoteRevocationAsync);
            }
            catch { _store.Dispose(); _gate.Dispose(); throw; }
        }
    }
    public async Task<EnrollmentManagementStatus> StatusAsync(CancellationToken token = default)
    { await _gate.WaitAsync(token).ConfigureAwait(false); try { return Status(); } finally { _gate.Release(); } }
    private EnrollmentManagementStatus Status()
    {
        var a = _store.Attempts.LastOrDefault();
        return new(a?.State ?? "idle", _identity.DeviceId, _origin, a?.InvitationId, a?.ErrorCode);
    }
    public async Task<EnrollmentManagementStatus> EnrollAsync(string text, CancellationToken token = default)
    {
        using var code = EnrollmentCode.Parse(text);
        if (code.RelayOrigin != _origin) throw new EnrollmentException("ENROLLMENT_ORIGIN_MISMATCH");
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var existing = _store.Attempts.SingleOrDefault(a => a.InvitationId == code.InvitationId);
            if (existing is not null)
            {
                if (existing.State is "revoked" or "cancelled" or "expired" or "faulted") throw new EnrollmentException("ENROLLMENT_INVITATION_CLOSED");
                if (existing.SecretBase64.Length != 0 && !CryptographicOperations.FixedTimeEquals(EnrollmentCrypto.Base64(existing.SecretBase64, 32), code.Secret))
                    throw new EnrollmentException("ENROLLMENT_CODE_INVALID");
                return new(existing.State, _identity.DeviceId, _origin, existing.InvitationId, existing.ErrorCode);
            }
            if (_store.Attempts.Any(a => a.State is "pending" or "claimed" or "committing" or "revoking")) throw new EnrollmentException("ENROLLMENT_ATTEMPT_ACTIVE");
            _store.Save(new(code.InvitationId, _origin, Convert.ToBase64String(code.Secret), "pending", _clock.GetUtcNow()));
            return Status();
        }
        finally { _gate.Release(); }
    }
    public async Task<EnrollmentManagementStatus> RevokeAsync(Guid invitationId, CancellationToken token = default)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var a = _store.Attempts.SingleOrDefault(a => a.InvitationId == invitationId) ?? throw new EnrollmentException("ENROLLMENT_NOT_FOUND");
            if (a.State is "revoked" or "cancelled" or "expired") return new(a.State, _identity.DeviceId, _origin, a.InvitationId, a.ErrorCode);
            if (a.State is "committing" or "bound" or "revoking")
            { a = a with { State = "revoking", SecretBase64 = "", ErrorCode = null }; _store.Save(a); await RevokeCoreAsync(a).ConfigureAwait(false); }
            else _store.Save(a with { State = "cancelled", SecretBase64 = "", ErrorCode = null });
            return Status();
        }
        finally { _gate.Release(); }
    }
    public async Task RunAsync(CancellationToken token)
    {
        while (true)
        {
            token.ThrowIfCancellationRequested();
            await StepAsync(token).ConfigureAwait(false);
            await Task.Delay(TimeSpan.FromSeconds(2), _clock, token).ConfigureAwait(false);
        }
    }
    internal async Task StepAsync(CancellationToken token = default)
    {
        // Polling an untrusted/offline mailbox must not hold the local management gate.
        if (_revocations is not null) await _revocations.StepAsync(token).ConfigureAwait(false);
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            foreach (var attempt in _store.Attempts.Where(a => a.State is "pending" or "claimed" or "committing" or "revoking").ToArray())
            {
                try
                {
                    if (attempt.State == "committing") { await CommitAsync(attempt, token).ConfigureAwait(false); continue; }
                    if (attempt.State == "revoking") { await RevokeCoreAsync(attempt).ConfigureAwait(false); continue; }
                    await AdvanceAsync(attempt, token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
                catch (TimeoutException) when (_store.Attempts.Single(a => a.InvitationId == attempt.InvitationId).State is "committing" or "revoking")
                {
                    var latest = _store.Attempts.Single(a => a.InvitationId == attempt.InvitationId);
                    var pending = latest.State == "revoking" ? "ENROLLMENT_REVOCATION_PENDING" : "ENROLLMENT_ACTIVATION_PENDING";
                    if (latest.ErrorCode != pending) _store.Save(latest with { ErrorCode = pending });
                }
                catch (Exception e) when (e is HttpRequestException or OperationCanceledException)
                {
                    var latest = _store.Attempts.Single(a => a.InvitationId == attempt.InvitationId);
                    if (latest.ErrorCode != "ENROLLMENT_RELAY_UNAVAILABLE") _store.Save(latest with { ErrorCode = "ENROLLMENT_RELAY_UNAVAILABLE" });
                }
                catch (Exception e) when (e is EnrollmentException or PairingStoreException or ControlPolicyException or CryptographicException)
                {
                    // Keep authorized partial commits resumable; never turn an incomplete transaction into successful binding.
                    var latest = _store.Attempts.Single(a => a.InvitationId == attempt.InvitationId);
                    if (latest.State is "committing" or "revoking") throw;
                    _store.Save(latest with { State = "faulted", SecretBase64 = "", ErrorCode = "ENROLLMENT_VERIFICATION_FAILED" });
                }
            }
        }
        finally { _gate.Release(); }
    }
    private async Task AdvanceAsync(EnrollmentAttempt a, CancellationToken token)
    {
        var receipt = await _relay.ExchangeAsync(a.ResponseBase64 is null ? "offer" : "receipt", a, _spki, token).ConfigureAwait(false);
        if (receipt.InvitationId != a.InvitationId) throw new EnrollmentException("ENROLLMENT_RECEIPT_MISMATCH");
        if (receipt.State is "expired" or "cancelled")
        { _store.Save(a with { State = receipt.State, SecretBase64 = "", ErrorCode = null }); return; }
        if (a.ResponseBase64 is null)
        {
            if (receipt.State != "pending" || receipt.ExpiresAtUnixSeconds <= _clock.GetUtcNow().ToUnixTimeSeconds()) throw new EnrollmentException("ENROLLMENT_INVITATION_CLOSED");
            using var code = a.OpenCode(); var offer = EnrollmentCrypto.Base64(receipt.OfferBase64);
            var (requestBytes, requestHash, request) = EnrollmentCrypto.ReadOffer(code, offer, _clock);
            if (receipt.ControllerDeviceId != request.ControllerDeviceID || receipt.ExpiresAtUnixSeconds > request.ExpiresAtUtc.ToUnixTimeSeconds())
                throw new EnrollmentException("ENROLLMENT_RECEIPT_MISMATCH");
            var current = await _pairings.FindAsync(request.ControllerDeviceID, token).ConfigureAwait(false);
            if (current is not null) throw new EnrollmentException("ENROLLMENT_PEER_ALREADY_PAIRED");
            for (var offset = 0; offset < 4096; offset += 64)
            {
                var page = _pairings.ListLocally(offset, 64);
                if (page.Any(p => p.PairingId == request.PairingID || p.ControllerDeviceId == request.ControllerDeviceID && p.RevokedAt is null))
                    throw new EnrollmentException("ENROLLMENT_PAIRING_CONFLICT");
                if (page.Count < 64) break;
            }
            if (_grants.ListLocally().Any(g => g.GrantId == request.GrantID)) throw new EnrollmentException("ENROLLMENT_GRANT_CONFLICT");
            var enrollment = JsonSerializer.SerializeToUtf8Bytes(new { version = 1, name = Environment.MachineName,
                installationState = "installedAwaitingRelayAdmission", relayURL = _origin, peerSPKIBase64 = _spki, peerDeviceID = _identity.DeviceId,
                pairingID = request.PairingID, grantID = request.GrantID, fileGrantID = request.FileGrantID, rdpGrantID = request.RdpGrantID,
                allowWindows10TLS12 = request.AllowWindows10TLS12 });
            var response = EnrollmentCrypto.Response(code, requestHash, enrollment, EnrollmentCrypto.Hash(offer));
            var transcript = EnrollmentCrypto.Transcript(a.InvitationId, request.ControllerDeviceID, offer, response, EnrollmentCrypto.Base64(_spki, 512));
            a = a with { OfferBase64 = receipt.OfferBase64, RequestBase64 = Convert.ToBase64String(requestBytes), RequestSha256 = requestHash,
                ControllerDeviceId = request.ControllerDeviceID, ResponseBase64 = Convert.ToBase64String(response),
                SignatureBase64 = Convert.ToBase64String(_identity.SignEnrollmentTranscript(transcript)), ClaimHash = EnrollmentCrypto.Hash(transcript),
                ExpiresAtUnixSeconds = receipt.ExpiresAtUnixSeconds, VerifiedAt = _clock.GetUtcNow(), ErrorCode = null };
            _store.Save(a); _checkpoint?.Invoke("response-persisted"); // Retry must reuse exactly this ciphertext and signature.
        }
        else VerifyReceipt(a, receipt);
        if (receipt.State == "bound") { await AuthorizeCommitAsync(a, receipt.Confirmation, token).ConfigureAwait(false); return; }
        // Expiry may not suppress a receipt lookup: a prior confirm can already have committed while its response was lost.
        if (receipt.ExpiresAtUnixSeconds <= _clock.GetUtcNow().ToUnixTimeSeconds())
        { _store.Save(a with { State = "expired", SecretBase64 = "", ErrorCode = null }); return; }
        var claimed = await _relay.ExchangeAsync("claim", a, _spki, token).ConfigureAwait(false);
        VerifyReceipt(a, claimed);
        if (claimed.State == "bound") { await AuthorizeCommitAsync(a, claimed.Confirmation, token).ConfigureAwait(false); return; }
        if (claimed.State != "claimed") throw new EnrollmentException("ENROLLMENT_RECEIPT_MISMATCH");
        _store.Save(a with { State = "claimed", ErrorCode = null });
    }
    private void VerifyReceipt(EnrollmentAttempt a, EnrollmentReceipt r)
    {
        if (r.InvitationId != a.InvitationId || r.ControllerDeviceId != a.ControllerDeviceId || r.OfferBase64 != a.OfferBase64
            || r.ExpiresAtUnixSeconds != a.ExpiresAtUnixSeconds) throw new EnrollmentException("ENROLLMENT_RECEIPT_MISMATCH");
        if (r.State is "claimed" or "bound")
        {
            if (r.Claim is not { } claim || claim.PeerSPKIBase64 != _spki || claim.ResponseBase64 != a.ResponseBase64
                || claim.SignatureBase64 != a.SignatureBase64 || claim.ClaimHash != a.ClaimHash) throw new EnrollmentException("ENROLLMENT_RECEIPT_MISMATCH");
        }
    }
    private async Task AuthorizeCommitAsync(EnrollmentAttempt a, EnrollmentConfirmation? confirmation, CancellationToken token)
    {
        if (confirmation is null) throw new EnrollmentException("ENROLLMENT_CONFIRMATION_REQUIRED");
        confirmation.Verify(a, VerifiedRequest(a), _identity.DeviceId, _clock);
        a = a with { State = "committing", ErrorCode = null, Confirmation = confirmation }; _store.Save(a); _checkpoint?.Invoke("commit-authorized"); await CommitAsync(a, token).ConfigureAwait(false);
    }
    private static RelayDelegatedEnrollment VerifiedRequest(EnrollmentAttempt a)
    {
        var bytes = EnrollmentCrypto.Base64(a.RequestBase64!, 16384);
        if (EnrollmentCrypto.Hash(bytes) != a.RequestSha256 || a.VerifiedAt is null) throw new EnrollmentException("ENROLLMENT_STATE_INVALID");
        return RelayDelegatedEnrollment.Parse(bytes, new FixedTime(a.VerifiedAt.Value));
    }
    private async Task CommitAsync(EnrollmentAttempt a, CancellationToken token)
    {
        var request = VerifiedRequest(a);
        if (a.Confirmation is null) throw new EnrollmentException("ENROLLMENT_CONFIRMATION_REQUIRED");
        a.Confirmation.Verify(a, request, _identity.DeviceId, _clock, recovery: true);
        _grants.ApproveLocally(new(request.ControllerDeviceID, request.GrantID, DateTimeOffset.MaxValue,
            Enum.GetValues<ControlOperation>(), ["powershell.v1"], allowDisconnected: true));
        _checkpoint?.Invoke("grant-persisted");
        _pairings.ApproveLocally(request.Pairing(), request.ControllerDeviceID); // Durable trust precedes runtime activation.
        _checkpoint?.Invoke("pairing-persisted");
        await _activatePairing(request.ControllerDeviceID, request.PairingID, token).ConfigureAwait(false);
        _checkpoint?.Invoke("pairing-activated");
        _store.Save(a with { State = "bound", SecretBase64 = "", ErrorCode = null });
    }
    private async Task RevokeCoreAsync(EnrollmentAttempt a)
    {
        var request = VerifiedRequest(a);
        await _revokePairing(request.ControllerDeviceID, request.PairingID, CancellationToken.None).ConfigureAwait(false);
        await _revokeGrant(request.ControllerDeviceID, request.GrantID, CancellationToken.None).ConfigureAwait(false);
        if (_drainPeer is not null) await _drainPeer(request.ControllerDeviceID, CancellationToken.None).ConfigureAwait(false);
        _store.Save(a with { State = "revoked", SecretBase64 = "", ErrorCode = null });
    }
    public void Dispose() { _revocations?.Dispose(); _store.Dispose(); if (_relay is IDisposable d) d.Dispose(); _gate.Dispose(); }
    private sealed class FixedTime(DateTimeOffset now) : TimeProvider { public override DateTimeOffset GetUtcNow() => now; }
}
