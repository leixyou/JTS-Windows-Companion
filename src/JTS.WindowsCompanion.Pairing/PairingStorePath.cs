namespace JTS.WindowsCompanion.Pairing;

internal static class PairingStorePath
{
    internal static string Validate(string path)
    {
        if (!Path.IsPathFullyQualified(path)) throw new ArgumentException("An absolute private pairing database path is required.");
        path = Path.GetFullPath(path); var parent = Path.GetDirectoryName(path)!;
        if (!Directory.Exists(parent)) throw new ArgumentException("Provision the protected directory before opening it.");
        foreach (var item in new[] { parent, path, path + ".lease", path + "-wal", path + "-shm" })
        {
            string? current = item;
            do
            {
                if (new FileInfo(current).LinkTarget is not null || ((File.Exists(current) || Directory.Exists(current))
                    && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0))
                    throw new ArgumentException("The pairing database path cannot traverse a reparse point.");
                current = OperatingSystem.IsWindows() ? Path.GetDirectoryName(current) : null;
            } while (!string.IsNullOrEmpty(current));
        }
        if (!OperatingSystem.IsWindows() && (File.GetUnixFileMode(parent) & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
            throw new ArgumentException("The pairing directory cannot be group/world writable.");
        return path;
    }
}
