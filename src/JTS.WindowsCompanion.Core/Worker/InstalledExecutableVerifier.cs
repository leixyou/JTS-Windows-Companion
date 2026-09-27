using System.Security.Cryptography;
using JTS.WindowsCompanion.Protocol;

namespace JTS.WindowsCompanion.Worker;

public interface IInstalledExecutableVerifier
{
    ValueTask VerifyAsync(
        string executablePath,
        string expectedSha256,
        CancellationToken cancellationToken);
}

public sealed class InstalledExecutableVerifier : IInstalledExecutableVerifier
{
    public async ValueTask VerifyAsync(
        string executablePath,
        string expectedSha256,
        CancellationToken cancellationToken)
    {
        var info = new FileInfo(executablePath);
        if (!info.Exists
            || (info.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw new CompanionProtocolException(
                "WORKER_EXECUTABLE_INVALID",
                "The installed VRC worker executable is missing or unsafe.");
        }

        if (OperatingSystem.IsWindows())
        {
            var root = Path.GetPathRoot(executablePath);
            if (string.IsNullOrEmpty(root) || new DriveInfo(root).DriveType != DriveType.Fixed)
            {
                throw new CompanionProtocolException(
                    "WORKER_EXECUTABLE_INVALID",
                    "The installed VRC worker executable must be on a fixed local volume.");
            }
        }

        await using var stream = new FileStream(
            executablePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var actual = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        var expected = Convert.FromHexString(expectedSha256);
        if (!CryptographicOperations.FixedTimeEquals(actual, expected))
        {
            throw new CompanionProtocolException(
                "WORKER_EXECUTABLE_CHANGED",
                "The installed VRC worker executable no longer matches its configured digest.");
        }
    }
}
