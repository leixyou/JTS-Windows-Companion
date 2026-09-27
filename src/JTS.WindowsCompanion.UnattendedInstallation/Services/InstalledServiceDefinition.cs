using JTS.WindowsCompanion.WorkerService;

namespace JTS.WindowsCompanion.UnattendedInstallation;

internal sealed record InstalledServiceDefinition(string Name, string DisplayName, string Executable,
    string AccountName, string AccountSid, string Description, string? ControllerSid, uint ActiveStartType)
{
    internal const string AuthorityName = "JTSCompanionAuthority25", WorkerName = "JTSCompanionWorker25";
    internal string Command => '"' + Executable + "\" --service";

    internal static (InstalledServiceDefinition Authority, InstalledServiceDefinition Worker) Create(
        LocalAccountIdentity authority, LocalAccountIdentity worker, string directory, Guid enrollment)
    {
        authority.Validate(); worker.Validate();
        if (enrollment == Guid.Empty || authority.EnrollmentId != enrollment || worker.EnrollmentId != enrollment
            || authority.Role != "authority" || worker.Role != "worker" || authority.Sid == worker.Sid
            || string.Equals(authority.Name, worker.Name, StringComparison.OrdinalIgnoreCase))
            throw new UnattendedInstallationException("INSTALL_SERVICE_BINDING_REJECTED");
        var prefix = directory.TrimEnd('\\') + '\\';
        var workerPath = prefix + "JTS.WindowsCompanion.WorkerRunner.exe";
        // Reuse the runtime's canonical local path/account/SID contract for both account identities.
        _ = new WorkerServiceInstallation(workerPath, @".\" + authority.Name, authority.Sid);
        _ = new WorkerServiceInstallation(workerPath, @".\" + worker.Name, worker.Sid);
        var marker = "JTS Companion 2.5 installation " + enrollment.ToString("D");
        return (
            new(AuthorityName, "JTS Companion 2.5 Authority", prefix + "JTS.WindowsCompanion.AuthorityService.exe",
                @".\" + authority.Name, authority.Sid, marker + " authority", null, 2),
            new(WorkerName, "JTS Companion 2.5 Worker", workerPath, @".\" + worker.Name, worker.Sid, marker + " worker", authority.Sid, 3));
    }
}
