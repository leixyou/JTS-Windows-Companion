using System.IO;
using System.Text;
using JTS.WindowsCompanion.Pairing;
using JTS.WindowsCompanion.UnattendedInstallation;

namespace JTS.WindowsCompanion.UnattendedSetup;

internal static class DelegatedSetup
{
    internal static int Run(string[] args, string bundle)
    {
        if (args is not ["--relay", var relay, "--delegated-enrollment", var input, "--sha256", var sha, "--export", var output])
            return 2;
        // Reserve an explicitly selected, new public output before any installation. Never overwrite an existing file.
        if (!Path.IsPathFullyQualified(input) || !Path.IsPathFullyQualified(output)) return 2;
        RejectLinks(input); RejectLinks(output);
        using var request = new FileStream(input, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (request.Length is < 1 or > RelayDelegatedEnrollment.MaximumBytes) return 2;
        var bytes = new byte[(int)request.Length]; request.ReadExactly(bytes);
        _ = RelayDelegatedEnrollment.Parse(bytes);
        using var export = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough);
        var result = WindowsUnattendedInstaller.InstallDelegatedAsync(bundle, relay, bytes, sha).GetAwaiter().GetResult();
        export.Write(Encoding.UTF8.GetBytes(result.PublicEnrollmentJson ?? throw new InvalidOperationException("INSTALL_PUBLIC_ENROLLMENT_MISSING")));
        export.Flush(flushToDisk: true);
        return 0;
    }
    private static void RejectLinks(string path)
    {
        for (string? entry = Path.GetFullPath(path); entry is not null; entry = Path.GetDirectoryName(entry))
            if ((File.Exists(entry) || Directory.Exists(entry)) && (File.GetAttributes(entry) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("INSTALL_LINK_REJECTED");
    }
}
