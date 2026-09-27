using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.UnattendedInstallation;

internal sealed class InstallationPayload : IDisposable
{
    internal static readonly string[] Names = ["JTS.WindowsCompanion.AuthorityService.exe", "JTS.WindowsCompanion.WorkerRunner.exe", "JTS.WindowsCompanion.AuthorityProvisioner.exe"];
    internal VerifiedReleaseManifest Manifest { get; }
    private readonly List<FileStream> _files = [];
    private readonly byte[] _manifest;
    private readonly string[] _names;
    internal InstallationPayload(string directory)
    {
        try
        {
            var path = Path.Combine(Path.GetFullPath(directory), ReleaseManifestTrust.ManifestFileName); InstallJournal.RejectLinks(path);
            var lease = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read); _files.Add(lease);
            if (lease.Length is < 1 or > 65536) throw new UnattendedInstallationException("INSTALL_PAYLOAD_REJECTED");
            _manifest = new byte[(int)lease.Length]; lease.ReadExactly(_manifest);
            Manifest = ReleaseManifestTrust.VerifyUsingEmbeddedKey(_manifest);
            _names = InstallationPayloadPlan.SelectFiles(Manifest.SchemaVersion, Manifest.FileNames);
            foreach (var name in _names) _files.Add(Manifest.OpenVerifiedFile(Path.Combine(directory, name), name));
        }
        catch { Dispose(); throw; }
    }
    internal void CopyNew(string protectedDirectory)
    {
        for (var i = 0; i < _names.Length; i++)
        {
            using var output = new FileStream(Path.Combine(protectedDirectory, _names[i]), FileMode.CreateNew, FileAccess.Write, FileShare.None, 131072, FileOptions.WriteThrough);
            _files[i + 1].Position = 0; _files[i + 1].CopyTo(output); output.Flush(flushToDisk: true);
        }
        using (var output = new FileStream(Path.Combine(protectedDirectory, ReleaseManifestTrust.ManifestFileName), FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        { output.Write(_manifest); output.Flush(flushToDisk: true); }
        foreach (var name in _names) Manifest.VerifyFile(Path.Combine(protectedDirectory, name), name);
    }
    public void Dispose() { foreach (var file in _files) file.Dispose(); _files.Clear(); }
}
