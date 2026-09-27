using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.UnattendedSetup;

internal sealed class SetupBundle : IDisposable
{
    internal const string ExecutableName = "JTS.WindowsCompanion.UnattendedSetup.exe";
    private readonly FileStream _manifest;
    private readonly FileStream _executable;
    internal string Directory { get; }

    private SetupBundle(string directory, FileStream manifest, FileStream executable)
    { Directory = directory; _manifest = manifest; _executable = executable; }

    internal static SetupBundle OpenCurrent()
    {
        var path = Environment.ProcessPath;
        if (path is null || !string.Equals(Path.GetFileName(path), ExecutableName, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("SETUP_EXECUTABLE_REJECTED");
        var directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
        var manifest = new FileStream(Path.Combine(directory, ReleaseManifestTrust.ManifestFileName),
            FileMode.Open, FileAccess.Read, FileShare.Read);
        try
        {
            // This verifies the actual single-file host, not an extracted assembly or an adjacent caller-supplied key.
            var release = ReleaseManifestTrust.LoadForExecutable(path);
            var executable = release.OpenVerifiedFile(path, ExecutableName);
            return new SetupBundle(directory, manifest, executable);
        }
        catch { manifest.Dispose(); throw; }
    }

    public void Dispose() { _executable.Dispose(); _manifest.Dispose(); }
}
