using System.Security.Cryptography;

namespace JTS.WindowsCompanion.Setup;

/// <summary>
/// Copies the running Setup without a circular self-hash in its embedded payload manifest.
/// The caller's trusted distribution channel authenticates the original Setup; this only
/// preserves its exact bytes during staging or a detached launch.
/// </summary>
internal sealed class LockedExecutableCopy : IDisposable
{
    private readonly FileStream _source;
    private readonly FileStream _copy;

    private LockedExecutableCopy(FileStream source, FileStream copy)
    {
        _source = source;
        _copy = copy;
    }

    public static LockedExecutableCopy Create(string sourcePath, string destinationPath)
    {
        var source = Path.GetFullPath(sourcePath);
        var destination = Path.GetFullPath(destinationPath);
        RejectReparseAncestors(source);
        RejectReparseAncestors(destination);
        FileStream? sourceLock = null;
        FileStream? copyLock = null;
        try
        {
            sourceLock = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read);
            RejectReparseAncestors(source);
            using (var output = new FileStream(
                       destination, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                       128 * 1024, FileOptions.WriteThrough))
            {
                sourceLock.CopyTo(output);
                output.Flush(flushToDisk: true);
            }

            RejectReparseAncestors(destination);
            copyLock = new FileStream(destination, FileMode.Open, FileAccess.Read, FileShare.Read);
            RejectReparseAncestors(destination);
            sourceLock.Position = 0;
            if (sourceLock.Length != copyLock.Length || !CryptographicOperations.FixedTimeEquals(
                    SHA256.HashData(sourceLock), SHA256.HashData(copyLock)))
            {
                throw new UnauthorizedAccessException("The temporary Setup copy differs from the running Setup.");
            }
            sourceLock.Position = 0;
            copyLock.Position = 0;
            return new LockedExecutableCopy(sourceLock, copyLock);
        }
        catch
        {
            copyLock?.Dispose();
            sourceLock?.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        _copy.Dispose();
        _source.Dispose();
    }

    private static void RejectReparseAncestors(string path)
    {
        string? current = path;
        while (!string.IsNullOrEmpty(current))
        {
            if ((File.Exists(current) || Directory.Exists(current)) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new UnauthorizedAccessException("Setup does not copy through a reparse point.");
            }
            // Windows is the runtime boundary; macOS test directories legitimately live below /var.
            current = OperatingSystem.IsWindows() ? Path.GetDirectoryName(current) : null;
        }
    }
}
