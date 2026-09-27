using System.Diagnostics;

namespace JTS.WindowsCompanion.Setup;

internal sealed class TemporarySetupLauncher
{
    private readonly string _setupExecutable;
    public TemporarySetupLauncher(string setupExecutable)
    {
        _setupExecutable = setupExecutable;
    }

    public Process Launch(string internalAction, bool quiet, bool purgeData = false,
        string? enrollmentPath = null, string? enrollmentSha256 = null)
    {
        using var preparedLaunch = TemporarySetupCleanupScheduler.PrepareTemporaryLaunch();
        var temporaryRoot = preparedLaunch.RootPath;
        var temporarySetup = Path.Combine(temporaryRoot, InstallerLayout.SetupFileName);
        var childStarted = false;
        try
        {
            using var executableCopy = LockedExecutableCopy.Create(_setupExecutable, temporarySetup);

            var startInfo = new ProcessStartInfo
            {
                FileName = temporarySetup,
                WorkingDirectory = temporaryRoot,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            startInfo.ArgumentList.Add(internalAction);
            if (quiet)
            {
                startInfo.ArgumentList.Add("--quiet");
            }
            if (purgeData)
            {
                startInfo.ArgumentList.Add("--purge-data");
            }
            if (enrollmentPath is not null)
            {
                startInfo.ArgumentList.Add("--delegated-enrollment");
                startInfo.ArgumentList.Add(enrollmentPath);
                startInfo.ArgumentList.Add("--delegated-enrollment-sha256");
                startInfo.ArgumentList.Add(enrollmentSha256!);
            }
            var child = Process.Start(startInfo)
                ?? throw new InvalidOperationException("The temporary setup process could not be started.");
            childStarted = true;
            preparedLaunch.ReleaseForCleanup();
            return child;
        }
        catch
        {
            preparedLaunch.ReleaseForCleanup();
            if (!childStarted)
            {
                TryDeleteTemporaryRoot(temporaryRoot);
            }
            throw;
        }
    }

    private static void TryDeleteTemporaryRoot(string temporaryRoot)
    {
        try
        {
            InstallerLayout.DeleteDirectoryWithoutFollowingLinks(temporaryRoot);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            // The already-running cleanup helper will retry after the launch sentinel closes.
        }
    }
}
