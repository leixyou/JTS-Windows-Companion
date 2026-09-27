using System.Security.Cryptography;
using JTS.WindowsCompanion.Control;
using JTS.WindowsCompanion.Pairing;
using JTS.WindowsCompanion.Relay;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.Enrollment;

public sealed partial class EnrollmentCoordinator
{
    /// <summary>Run before constructing any control host or executor. No network, process launch, pairing approval or success receipt.</summary>
    public static void PrepareStartup(string path, string origin, string deviceId, ITaskPayloadProtector protector,
        Action<string> checkPath, DurableRelayPairingStore pairings, DurableControlGrantStore grants)
        => PrepareStartupCore(path, origin, deviceId, protector, checkPath, pairings, grants, TimeProvider.System, null);

    internal static void PrepareStartupCore(string path, string origin, string deviceId, ITaskPayloadProtector protector,
        Action<string> checkPath, DurableRelayPairingStore pairings, DurableControlGrantStore grants, TimeProvider clock, Action<string>? checkpoint)
    {
        origin = EnrollmentCode.CanonicalOrigin(origin);
        if (pairings.LocalDeviceId != deviceId) throw new EnrollmentException("ENROLLMENT_IDENTITY_MISMATCH");
        using var attempts = new EnrollmentAttemptStore(path, deviceId, protector, checkPath);
        foreach (var a in attempts.Attempts.Where(a => a.State is "committing" or "bound" or "revoking").ToArray())
        {
            var request = VerifiedRequest(a);
            if (a.RelayOrigin != origin || a.ControllerDeviceId != request.ControllerDeviceID) throw new EnrollmentException("ENROLLMENT_STATE_INVALID");
            if (a.Confirmation is not null) a.Confirmation.Verify(a, request, deviceId, clock, recovery: true);
            if (a.State != "revoking" && a.Confirmation is not null) continue;
            var legacy = a.Confirmation is null;
            var pending = a with { State = "revoking", SecretBase64 = "", ErrorCode = legacy ? "ENROLLMENT_LEGACY_CONFIRMATION_REQUIRED" : a.ErrorCode };
            attempts.Save(pending); checkpoint?.Invoke("startup-revocation-journaled");
            RevokePersistedEpoch(pairings, grants, request.ControllerDeviceID, request.PairingID, request.GrantID, checkpoint);
            // Legacy unsigned authorization is permanently retired. A new code preserves the Windows identity but uses fresh grant IDs.
            if (legacy) attempts.Save(pending with { State = "revoked" });
        }
        using var revocations = new RevocationJournal(path + ".revocations", deviceId, protector, checkPath);
        foreach (var entry in revocations.Entries.Where(e => e.Receipt is null && !e.Rejected).ToArray())
        {
            try
            {
                var request = entry.Delivery.Revocation; request.Verify(origin, deviceId, entry.Delivery.ControllerSPKIBase64);
                var (attempt, _) = MatchRevocation(request, attempts, pairings);
                if (attempt is not null && attempt.State != "revoked")
                    attempts.Save(attempt with { State = "revoking", SecretBase64 = "", ErrorCode = "ENROLLMENT_REVOCATION_PENDING" });
                RevokePersistedEpoch(pairings, grants, request.ControllerDeviceId, RevocationRequest.Id(request.PairingId), RevocationRequest.Id(request.GrantId), checkpoint);
                // Live cancellation/drain still occurs after startup. Do not create or deliver a completion in this phase.
            }
            catch (Exception e) when (e is EnrollmentException or CryptographicException)
            { revocations.Save(entry with { Rejected = true }); }
        }
    }

    private static void RevokePersistedEpoch(DurableRelayPairingStore pairings, DurableControlGrantStore grants,
        string owner, Guid epoch, Guid grant, Action<string>? checkpoint)
    {
        var record = FindEpoch(pairings, epoch);
        var current = pairings.FindAsync(owner).GetAwaiter().GetResult();
        if (current is not null && current.PairingId != epoch)
        { if (record?.ControllerDeviceId != owner || record.RevokedAt is null) throw RevocationRequest.Invalid(); }
        else pairings.RevokeAsync(owner, epoch).GetAwaiter().GetResult();
        checkpoint?.Invoke("startup-pairing-revoked");
        grants.RevokeAsync(owner, grant, CancellationToken.None).GetAwaiter().GetResult();
        checkpoint?.Invoke("startup-grant-revoked");
    }

    private static RelayPairingRecord? FindEpoch(DurableRelayPairingStore pairings, Guid epoch)
    {
        for (var offset = 0; offset < 4096; offset += 64)
        {
            var page = pairings.ListLocally(offset, 64); var record = page.SingleOrDefault(p => p.PairingId == epoch);
            if (record is not null || page.Count < 64) return record;
        }
        return null;
    }
    private static (EnrollmentAttempt? Attempt, RelayPairingRecord? Record) MatchRevocation(RevocationRequest request,
        EnrollmentAttemptStore attempts, DurableRelayPairingStore pairings)
    {
        var epoch = RevocationRequest.Id(request.PairingId); var record = FindEpoch(pairings, epoch);
        var attempt = attempts.Attempts.SingleOrDefault(a => a.RequestBase64 is not null && a.ControllerDeviceId == request.ControllerDeviceId
            && VerifiedRequest(a).PairingID == epoch);
        var expected = record?.Policy ?? (attempt is not null ? VerifiedRequest(attempt).Pairing() : null);
        if (expected is null || expected.ControllerDeviceId != request.ControllerDeviceId
            || !expected.GrantsFor(RelayLane.Control).SequenceEqual(new[] { RevocationRequest.Id(request.GrantId) })
            || !expected.GrantsFor(RelayLane.File).SequenceEqual(new[] { RevocationRequest.Id(request.FileGrantId) })
            || !expected.GrantsFor(RelayLane.Rdp).SequenceEqual(new[] { RevocationRequest.Id(request.RdpGrantId) })) throw RevocationRequest.Invalid();
        return (attempt, record);
    }
}
