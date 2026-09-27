using System.Runtime.Versioning;
using System.Security.Principal;
using JTS.WindowsCompanion.Control;
using JTS.WindowsCompanion.Enrollment;
using JTS.WindowsCompanion.Execution;
using JTS.WindowsCompanion.Pairing;
using JTS.WindowsCompanion.Relay;
using JTS.WindowsCompanion.Runtime;
using JTS.WindowsCompanion.WorkerIpc;
using JTS.WindowsCompanion.WorkerService;

namespace JTS.WindowsCompanion.AuthorityService;

[SupportedOSPlatform("windows")]
internal static class WindowsAuthorityRuntime
{
    internal static IAuthorityRuntime Open(CancellationToken stop)
    {
        stop.ThrowIfCancellationRequested();
        using var token = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        var account = token.User?.Value ?? throw new AuthorityException("AUTHORITY_ACCOUNT_REQUIRED");
        WindowsStandardAccount.RestrictServiceCurrent(account);
        var resources = new List<IDisposable>();
        try
        {
            var executable = Environment.ProcessPath ?? throw new AuthorityException("AUTHORITY_PROGRAM_REQUIRED");
            resources.Add(WindowsServiceProgramTrust.Open(executable, CompanionServiceProgram.Authority));
            var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "JTS Terminal", "Companion25", "authority");
            var configPath = WindowsProtectedDataPath.Require(Path.Combine(root, "authority.json"), account);
            var configLease = new FileStream(configPath, FileMode.Open, FileAccess.Read, FileShare.Read); resources.Add(configLease);
            if (configLease.Length is < 1 or > AuthorityConfiguration.MaximumBytes) throw new AuthorityException("AUTHORITY_CONFIGURATION_INVALID");
            var bytes = new byte[(int)configLease.Length]; configLease.ReadExactly(bytes);
            var config = AuthorityConfiguration.Parse(bytes);
            if (config.AuthoritySid != account) throw new AuthorityException("AUTHORITY_ACCOUNT_MISMATCH");
            // All state must already exist. Startup never provisions, repairs, approves or migrates it.
            string State(string name) => WindowsProtectedDataPath.Require(Path.Combine(root, name), account);
            var identityPath = State("identity.sealed"); var pairingPath = State("pairings.sqlite");
            var grantsPath = State("control-grants.sqlite"); var jobsPath = State("jobs.sqlite");
            var identity = WindowsRelayIdentityStore.Open(identityPath, config.EnrollmentId, account, config.DeviceId); resources.Add(identity);
            if (identity.Description.CertificateExpiresAt <= DateTimeOffset.UtcNow + AuthorityTiming.Default.ExpiryLead)
                throw new AuthorityException("AUTHORITY_IDENTITY_RENEWAL_REQUIRED");
            var protector = new CurrentUserDpapiTaskProtector();
            var pairings = new DurableRelayPairingStore(pairingPath, config.DeviceId, protector); resources.Add(pairings);
            var grants = new DurableControlGrantStore(grantsPath, protector); resources.Add(grants);
            var jobs = new DurableJobStore(jobsPath, protector); resources.Add(jobs);
            // Recheck newly created SQLite auxiliary files, then validate Worker image before creating an executing host.
            State("pairings.sqlite"); State("control-grants.sqlite"); State("jobs.sqlite");
            using (WindowsServiceProgramTrust.Open(config.Worker.ExecutablePath, CompanionServiceProgram.Worker)) { }
            var executor = new WindowsWorkerJobExecutor(config.Worker.AccountSid, new WindowsScmWorkerLauncher(config.Worker));
            var relay = new RelayControlClient(config.RelayOrigin, identity.Identity); resources.Add(relay);
            var spool = State("transfers"); Directory.CreateDirectory(spool); State("transfers");
            var shared = Path.Combine(Path.GetDirectoryName(root)!, "shared");
            var files = new RelayFileLane(pairings, shared, spool);
            resources.Add(new AsyncResource(files));
            stop.ThrowIfCancellationRequested();
            var service = new CompanionRelayControlService(relay, jobs, grants, new DurableControlRelayPairings(pairings), executor,
                lanes: new Dictionary<RelayLane, ICompanionRelayLaneHandler> { [RelayLane.File] = files, [RelayLane.Rdp] = new RelayRdpLane(pairings) },
                waitForRelayAdmission: true);
            var enrollment = new EnrollmentCoordinator(State("enrollment-attempts.sealed"), config.RelayOrigin.AbsoluteUri,
                identity.Description.PublicKeySpkiBase64, identity.Identity, protector, p => { WindowsProtectedDataPath.Require(p, account); },
                pairings, grants, service.RevokePairingAsync, service.RevokeGrantDurablyAsync, service.ActivatePairingAsync, relay, service.DrainRevokedPeerAsync);
            resources.Add(enrollment);
            var management = new WindowsEnrollmentManagementServer(account, enrollment);
            return AuthorityRuntime.Own(service, identity.Description.CertificateExpiresAt, resources, enrollment.RunAsync, management.RunAsync);
        }
        catch
        {
            foreach (var resource in resources.AsEnumerable().Reverse()) try { resource.Dispose(); } catch { }
            throw;
        }
    }
    private sealed class AsyncResource(IAsyncDisposable value) : IDisposable
    { public void Dispose() => value.DisposeAsync().AsTask().GetAwaiter().GetResult(); }
}
