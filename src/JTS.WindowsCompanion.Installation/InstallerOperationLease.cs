using System.Diagnostics;

namespace JTS.WindowsCompanion.Setup;

internal sealed class InstallerOperationLease : IDisposable
{
    private readonly FileStream _stream;
    private bool _disposed;

    private InstallerOperationLease(string lockPath, FileStream stream)
    {
        LockPath = Path.GetFullPath(lockPath);
        _stream = stream;
    }

    public string LockPath { get; }

    public static InstallerOperationLease? TryAcquire(
        string lockPath,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        if (timeout < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        var normalizedPath = Path.GetFullPath(lockPath);
        var parent = Directory.GetParent(normalizedPath)?.FullName
            ?? throw new InvalidDataException("The setup operation lock has no parent.");
        Directory.CreateDirectory(parent);
        RejectReparsePoint(parent);
        RejectReparsePointIfPresent(normalizedPath);

        var stopwatch = Stopwatch.StartNew();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var stream = new FileStream(
                    normalizedPath,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    bufferSize: 1,
                    FileOptions.WriteThrough);
                try
                {
                    RejectReparsePointIfPresent(normalizedPath);
                    return new InstallerOperationLease(normalizedPath, stream);
                }
                catch
                {
                    stream.Dispose();
                    throw;
                }
            }
            catch (IOException) when (stopwatch.Elapsed < timeout)
            {
                var remaining = timeout - stopwatch.Elapsed;
                var delay = remaining < TimeSpan.FromMilliseconds(50)
                    ? remaining
                    : TimeSpan.FromMilliseconds(50);
                if (delay > TimeSpan.Zero)
                {
                    cancellationToken.WaitHandle.WaitOne(delay);
                }
            }
            catch (IOException)
            {
                return null;
            }
        }
    }

    public void DemandProtects(string protectedPath)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var lockParent = Directory.GetParent(LockPath)?.FullName
            ?? throw new InvalidDataException("The setup operation lock has no parent.");
        var protectedParent = Directory.GetParent(Path.GetFullPath(protectedPath))?.FullName
            ?? throw new InvalidDataException("The protected setup path has no parent.");
        if (!string.Equals(lockParent, protectedParent, StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException("The setup operation lease does not protect this path.");
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        _stream.Dispose();
    }

    private static void RejectReparsePoint(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new UnauthorizedAccessException("Setup does not lock through a symbolic link or reparse point.");
        }
    }

    private static void RejectReparsePointIfPresent(string path)
    {
        if ((File.Exists(path) || Directory.Exists(path)) &&
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new UnauthorizedAccessException("Setup does not use a symbolic link or reparse point as its operation lock.");
        }
    }
}
