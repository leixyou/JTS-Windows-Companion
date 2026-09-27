using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Control;
using JTS.WindowsCompanion.Pairing;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.AuthorityProvisioner;

internal interface IProvisioningIdentityFactory
{
    StoredRelayIdentity Create(string path, ProvisioningIntent intent);
    StoredRelayIdentity Open(string path, ProvisioningIntent intent, string deviceId);
}

// Injection is internal and test-only. The executable fixes Windows token, program, ACL and CurrentUser DPAPI policy.
internal sealed class ProvisioningState(ITaskPayloadProtector protector, IProvisioningIdentityFactory identities,
    Action<string> requirePrivatePath, TimeProvider clock)
{
    private static readonly string[] StateNames = ["identity.sealed", "pairings.sqlite", "control-grants.sqlite", "jobs.sqlite"];
    internal void Create(ProvisioningPaths paths, ProvisioningIntent intent, byte[]? delegationBytes = null)
    {
        if (paths.EnrollmentId != intent.EnrollmentId) throw new ProvisioningException("PROVISION_ENROLLMENT_MISMATCH");
        intent.RequireCurrent(clock); paths.RequireStagingOnly();
        RelayDelegatedEnrollment? delegation = null;
        if (intent.DelegationSha256 is not null)
        {
            if (delegationBytes is null || Convert.ToHexStringLower(SHA256.HashData(delegationBytes)) != intent.DelegationSha256)
                throw new ProvisioningException("PROVISION_DELEGATION_INVALID");
            delegation = RelayDelegatedEnrollment.Parse(delegationBytes, clock);
        }
        else if (delegationBytes is not null) throw new ProvisioningException("PROVISION_DELEGATION_INVALID");
        var attemptPath = paths.FilePath("attempt.json"); requirePrivatePath(attemptPath);
        // The durable marker also acts as an exclusive in-flight lease. Neither success nor failure erases it.
        using var attempt = new FileStream(attemptPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
        attempt.Write(JsonSerializer.SerializeToUtf8Bytes(new { schemaVersion = 1, enrollmentId = intent.EnrollmentId, state = "attempted" }));
        attempt.Flush(flushToDisk: true);
        if (Directory.EnumerateFileSystemEntries(paths.State).Any(p => Path.GetFileName(p) != "attempt.json"))
            throw new ProvisioningException("PROVISION_STAGE_NOT_EMPTY");
        string StatePath(string name) { var path = paths.FilePath(name); requirePrivatePath(path); return path; }
        RelayIdentityDescription description;
        using (var identity = identities.Create(StatePath("identity.sealed"), intent)) description = identity.Description;
        using (var pairings = DurableRelayPairingStore.CreateNew(StatePath("pairings.sqlite"), description.DeviceId, protector, clock: clock))
        using (var grants = DurableControlGrantStore.CreateNew(StatePath("control-grants.sqlite"), protector, clock: clock))
        {
            if (delegation is not null)
            {
                pairings.ApproveDelegatedInstallation(delegation);
                grants.ApproveLocally(new(delegation.ControllerDeviceID, delegation.GrantID, DateTimeOffset.MaxValue,
                    Enum.GetValues<ControlOperation>(), ["powershell.v1"], allowDisconnected: true));
                var delegationReceipt = JsonSerializer.SerializeToUtf8Bytes(new { version = 1, authorizationSource = "ownerDelegated",
                    authorizationReference = "device-ai-control-enabled", requestSha256 = intent.DelegationSha256,
                    authoritySid = intent.AuthoritySid, approvedAtUtc = clock.GetUtcNow(), windowsIdentity = description, delegation });
                File.WriteAllBytes(StatePath("delegation-receipt.json"), delegationReceipt);
            }
        }
        using (DurableJobStore.CreateNew(StatePath("jobs.sqlite"), protector)) { }
        // Reopen sealed identity and each authenticated store after all original handles have closed.
        using (var identity = identities.Open(StatePath("identity.sealed"), intent, description.DeviceId))
        using (var pairings = new DurableRelayPairingStore(StatePath("pairings.sqlite"), description.DeviceId, protector))
        using (var grants = new DurableControlGrantStore(StatePath("control-grants.sqlite"), protector))
        using (var jobs = new DurableJobStore(StatePath("jobs.sqlite"), protector))
        {
            if (identity.Description != description || description.CertificateExpiresAt <= clock.GetUtcNow() + TimeSpan.FromDays(1)
                || pairings.ListLocally().Count != (delegation is null ? 0 : 1) || grants.ListLocally().Count != (delegation is null ? 0 : 1) || jobs.GetRecoveryRequirement() is not null)
                throw new ProvisioningException("PROVISION_STATE_VERIFICATION_FAILED");
        }
        // A closed WAL store must not need sidecars to publish. Do not delete unexplained files or repair state.
        var stateNames = delegation is null ? StateNames : StateNames.Append("delegation-receipt.json").ToArray();
        var allowed = stateNames.Concat(StateNames.Select(n => n + ".lease")).Append("attempt.json").ToHashSet(StringComparer.Ordinal);
        foreach (var entry in Directory.EnumerateFileSystemEntries(paths.State))
        {
            ProvisioningPaths.RejectLinks(entry); requirePrivatePath(entry);
            if (!allowed.Contains(Path.GetFileName(entry)) || Directory.Exists(entry))
                throw new ProvisioningException("PROVISION_UNEXPECTED_STATE");
        }
        var files = stateNames.Select(name => DescribeFile(StatePath(name), name)).ToArray();
        var receipt = JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = 1, enrollmentId = intent.EnrollmentId, state = "staged-not-enabled", authoritySid = intent.AuthoritySid,
            workerSid = intent.WorkerSid, preparedAt = clock.GetUtcNow(), identity = description, files,
        });
        var pending = StatePath("ready.pending.json");
        using (var output = new FileStream(pending, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        { output.Write(receipt); output.Flush(flushToDisk: true); }
        intent.RequireCurrent(clock); paths.RequireStagingOnly();
        requirePrivatePath(pending); var ready = StatePath("ready.json");
        File.Move(pending, ready, overwrite: false);
        // No directory publication, authority.json, service operation, networking, pairing or capability grant here.
    }
    private static object DescribeFile(string path, string name)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is < 1 or > 16777216) throw new ProvisioningException("PROVISION_STATE_SIZE_REJECTED");
        return new { name, bytes = stream.Length, sha256 = Convert.ToHexStringLower(SHA256.HashData(stream)) };
    }
}
