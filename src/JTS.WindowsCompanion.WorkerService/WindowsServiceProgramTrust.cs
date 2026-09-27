using System.Runtime.Versioning;
using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.WorkerService;

public enum CompanionServiceProgram { Worker, Authority, AuthorityProvisioner }

/// <summary>Locks one embedded-manifest-verified, protected service executable. No process launch or trust-key override.</summary>
[SupportedOSPlatform("windows")]
public static class WindowsServiceProgramTrust
{
    public static FileStream Open(string path, CompanionServiceProgram program)
    {
        var name = program switch
        {
            CompanionServiceProgram.Worker => "JTS.WindowsCompanion.WorkerRunner.exe",
            CompanionServiceProgram.Authority => "JTS.WindowsCompanion.AuthorityService.exe",
            CompanionServiceProgram.AuthorityProvisioner => "JTS.WindowsCompanion.AuthorityProvisioner.exe",
            _ => throw new ArgumentOutOfRangeException(nameof(program)),
        };
        if (!string.Equals(Path.GetFileName(path), name, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("SERVICE_PROGRAM_NAME_REJECTED");
        var manifest = ReleaseManifestTrust.LoadForExecutable(path);
        var file = manifest.OpenVerifiedFile(path, name);
        try { WindowsServiceInspection.VerifyProgramAcl(path); return file; }
        catch { file.Dispose(); throw; }
    }
}
