using JTS.WindowsCompanion.Pairing;
using JTS.WindowsCompanion.Relay;

namespace JTS.WindowsCompanion.Enrollment;

public sealed partial class EnrollmentCoordinator
{
    private readonly RevocationProcessor? _revocations;
    private readonly Func<string, CancellationToken, ValueTask>? _drainPeer;

    private async Task ApplyRemoteRevocationAsync(RevocationRequest request, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try { await ApplyRemoteRevocationCoreAsync(request, token).ConfigureAwait(false); }
        finally { _gate.Release(); }
    }

    private async Task ApplyRemoteRevocationCoreAsync(RevocationRequest request, CancellationToken token)
    {
        var epoch = RevocationRequest.Id(request.PairingId); var grant = RevocationRequest.Id(request.GrantId);
        var (attempt, record) = MatchRevocation(request, _store, _pairings);
        if (attempt is not null && attempt.State != "revoked")
        { attempt = attempt with { State = "revoking", SecretBase64 = "", ErrorCode = null }; _store.Save(attempt); }
        var current = await _pairings.FindAsync(request.ControllerDeviceId, token).ConfigureAwait(false);
        if (current is not null && current.PairingId != epoch)
        {
            // A delayed old request may confirm its existing tombstone, but must never cancel a newer epoch.
            if (record?.RevokedAt is null) throw RevocationRequest.Invalid();
            await _grants.RevokeAsync(request.ControllerDeviceId, grant, token).ConfigureAwait(false);
        }
        else
        {
            await _revokePairing(request.ControllerDeviceId, epoch, token).ConfigureAwait(false);
            await _revokeGrant(request.ControllerDeviceId, grant, CancellationToken.None).ConfigureAwait(false);
            await _drainPeer!(request.ControllerDeviceId, token).ConfigureAwait(false);
        }
        if (attempt is not null) _store.Save(attempt with { State = "revoked", SecretBase64 = "", ErrorCode = null });
    }
}
