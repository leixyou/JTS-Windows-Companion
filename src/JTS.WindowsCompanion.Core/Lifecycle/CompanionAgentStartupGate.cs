using System.Diagnostics;
using System.Security.Cryptography;

namespace JTS.WindowsCompanion.Lifecycle;

internal enum CompanionAgentStartupGateResult
{
    Continue,
    Superseded,
    TimedOut,
}

internal static class CompanionAgentStartupGate
{
    public static CompanionAgentStartupGateResult WaitForStableInstalledImage(
        string executablePath,
        string expectedInstalledExecutablePath,
        string operationLockPath,
        TimeSpan timeout)
    {
        if (timeout < TimeSpan.Zero && timeout != Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        var executable = Path.GetFullPath(executablePath);
        var expectedExecutable = Path.GetFullPath(expectedInstalledExecutablePath);
        if (!string.Equals(executable, expectedExecutable, StringComparison.OrdinalIgnoreCase))
        {
            return CompanionAgentStartupGateResult.Continue;
        }

        var lockPath = Path.GetFullPath(operationLockPath);
        ValidateLayout(expectedExecutable, lockPath);
        var initialHash = TryHashExecutable(executable);
        if (initialHash is null)
        {
            return CompanionAgentStartupGateResult.Superseded;
        }

        var stopwatch = Stopwatch.StartNew();
        var waitIndefinitely = timeout == Timeout.InfiniteTimeSpan;
        while (true)
        {
            try
            {
                RejectReparsePointIfPresent(lockPath);
                using var operationGate = new FileStream(
                    lockPath,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    bufferSize: 1,
                    FileOptions.None);
                RejectReparsePointIfPresent(lockPath);
                var installedHash = TryHashExecutable(expectedExecutable);
                return installedHash is not null &&
                       CryptographicOperations.FixedTimeEquals(initialHash, installedHash)
                    ? CompanionAgentStartupGateResult.Continue
                    : CompanionAgentStartupGateResult.Superseded;
            }
            catch (IOException) when (waitIndefinitely || stopwatch.Elapsed < timeout)
            {
                var delay = waitIndefinitely
                    ? TimeSpan.FromMilliseconds(50)
                    : timeout - stopwatch.Elapsed < TimeSpan.FromMilliseconds(50)
                        ? timeout - stopwatch.Elapsed
                        : TimeSpan.FromMilliseconds(50);
                if (delay > TimeSpan.Zero)
                {
                    Thread.Sleep(delay);
                }
            }
            catch (IOException)
            {
                return CompanionAgentStartupGateResult.TimedOut;
            }
        }
    }

    private static byte[]? TryHashExecutable(string path)
    {
        try
        {
            if (!File.Exists(path) ||
                (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                return null;
            }
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read | FileShare.Delete,
                bufferSize: 128 * 1024,
                FileOptions.SequentialScan);
            return SHA256.HashData(stream);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static void ValidateLayout(string executablePath, string lockPath)
    {
        var installRoot = Directory.GetParent(executablePath)?.FullName
            ?? throw new InvalidDataException("The installed Companion executable has no parent directory.");
        var installParent = Directory.GetParent(installRoot)?.FullName
            ?? throw new InvalidDataException("The installed Companion directory has no parent.");
        var lockParent = Directory.GetParent(lockPath)?.FullName
            ?? throw new InvalidDataException("The Companion setup operation lock has no parent.");
        if (!string.Equals(installParent, lockParent, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                Path.GetFileName(lockPath),
                CompanionInstallationContract.OperationLockFileName,
                StringComparison.Ordinal))
        {
            throw new UnauthorizedAccessException(
                "The Companion startup gate is outside the installation parent.");
        }
    }

    private static void RejectReparsePointIfPresent(string path)
    {
        if ((File.Exists(path) || Directory.Exists(path)) &&
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new UnauthorizedAccessException(
                "The Companion startup gate does not use a symbolic link or reparse point.");
        }
    }
}
