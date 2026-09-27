using JTS.WindowsCompanion.Setup;

namespace JTS.WindowsCompanion.Tests;

public sealed class TemporarySetupCleanupSchedulerTests
{
    [Fact]
    public void CreateTemporaryRoot_ProducesAnExactlyRecognizedSetupPath()
    {
        var root = TemporarySetupCleanupScheduler.CreateTemporaryRoot();
        try
        {
            var executable = Path.Combine(root, InstallerLayout.SetupFileName);

            var identified = TemporarySetupCleanupScheduler.IdentifyTemporaryRoot(executable);

            Assert.Equal(Path.GetFullPath(root), identified);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public void IdentifyTemporaryRoot_RejectsWrongExecutableAndLookalikeDirectory()
    {
        var temporaryParent = Path.GetFullPath(Path.GetTempPath());
        var lookalike = Path.Combine(
            temporaryParent,
            "JTS-Windows-Companion-Setup-not-a-guid");

        Assert.Null(TemporarySetupCleanupScheduler.IdentifyTemporaryRoot(
            Path.Combine(lookalike, InstallerLayout.SetupFileName)));
        Assert.Null(TemporarySetupCleanupScheduler.IdentifyTemporaryRoot(
            Path.Combine(
                temporaryParent,
                $"JTS-Windows-Companion-Setup-{Guid.NewGuid():N}",
                "unrelated.exe")));
    }

    [Fact]
    public void IdentifyTemporaryRoot_RejectsAValidNameOutsideTheSystemTempParent()
    {
        var normalizedTemporaryParent = Path.GetFullPath(Path.GetTempPath())
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var outside = Path.Combine(
            Directory.GetParent(normalizedTemporaryParent)?.FullName
                ?? Path.GetPathRoot(Path.GetTempPath())!,
            "outside-jts-setup-tests",
            $"JTS-Windows-Companion-Setup-{Guid.NewGuid():N}");

        Assert.Null(TemporarySetupCleanupScheduler.IdentifyTemporaryRoot(
            Path.Combine(outside, InstallerLayout.SetupFileName)));
    }

    [Fact]
    public void LaunchSentinel_RemainsUntilTheCleanupHelperDeletesIt()
    {
        var root = TemporarySetupCleanupScheduler.CreateTemporaryRoot();
        try
        {
            var sentinelPath = Path.Combine(
                root,
                TemporarySetupCleanupScheduler.LaunchSentinelName);

            using (TemporarySetupCleanupScheduler.CreateLaunchSentinel(root))
            {
                Assert.True(File.Exists(sentinelPath));
            }

            Assert.True(File.Exists(sentinelPath));
            File.Delete(sentinelPath);
            Assert.False(File.Exists(sentinelPath));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public void LaunchSentinel_RejectsAnInvalidOwnershipMarker()
    {
        var root = TemporarySetupCleanupScheduler.CreateTemporaryRoot();
        try
        {
            File.WriteAllText(
                Path.Combine(root, ".jts-temporary-setup-v1"),
                "not owned by JTS");

            Assert.Throws<UnauthorizedAccessException>(
                () => TemporarySetupCleanupScheduler.CreateLaunchSentinel(root));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public void LaunchSentinel_RejectsAnOwnedLookalikeDirectoryName()
    {
        var generatedRoot = TemporarySetupCleanupScheduler.CreateTemporaryRoot();
        var lookalikeRoot = generatedRoot + "-lookalike";
        Directory.Move(generatedRoot, lookalikeRoot);
        try
        {
            Assert.Throws<UnauthorizedAccessException>(
                () => TemporarySetupCleanupScheduler.CreateLaunchSentinel(lookalikeRoot));
        }
        finally
        {
            if (Directory.Exists(lookalikeRoot))
            {
                Directory.Delete(lookalikeRoot, recursive: true);
            }
        }
    }

    [Fact]
    public void CleanupScript_HasABoundedRetryLimitAndAlwaysExits()
    {
        var lines = TemporarySetupCleanupScheduler.CreateCleanupScriptLines();

        Assert.Contains(
            $"if %JTS_TEMP_SETUP_CLEANUP_ATTEMPTS% GEQ {TemporarySetupCleanupScheduler.MaximumCleanupAttempts} goto exhausted",
            lines);
        Assert.Equal(1, lines.Count(line => string.Equals(line, "goto retry", StringComparison.Ordinal)));
        Assert.Contains(":cleaned", lines);
        Assert.Contains("exit /b 0", lines);
        Assert.Contains(":exhausted", lines);
        Assert.Contains("exit /b 1", lines);
        Assert.Equal(
            2,
            lines.Count(line => string.Equals(
                line,
                "del /f /q \"%~f0\" >nul 2>nul",
                StringComparison.Ordinal)));
    }

    [Fact]
    public void CleanupScript_NeverRemovesTheRootWhileTheLaunchSentinelExists()
    {
        var lines = TemporarySetupCleanupScheduler.CreateCleanupScriptLines().ToList();
        var sentinelDelete = lines.IndexOf(
            $"del /f /q \"%JTS_TEMP_SETUP_CLEANUP_ROOT%\\{TemporarySetupCleanupScheduler.LaunchSentinelName}\" >nul 2>nul");
        var sentinelGuard = lines.IndexOf(
            $"if exist \"%JTS_TEMP_SETUP_CLEANUP_ROOT%\\{TemporarySetupCleanupScheduler.LaunchSentinelName}\" goto wait");
        var remove = lines.IndexOf(
            "rmdir /s /q \"%JTS_TEMP_SETUP_CLEANUP_ROOT%\" >nul 2>nul");

        Assert.InRange(sentinelDelete, 0, sentinelGuard - 1);
        Assert.InRange(sentinelGuard, sentinelDelete + 1, remove - 1);
        Assert.Equal(1, lines.Count(line => line.StartsWith("rmdir ", StringComparison.Ordinal)));
        Assert.Contains(
            "if not exist \"%JTS_TEMP_SETUP_CLEANUP_ROOT%\\.jts-temporary-setup-v1\" goto exhausted",
            lines);
        Assert.Contains(
            "\"%JTS_TEMP_SETUP_SYSTEM_DIRECTORY%\\findstr.exe\" /x /l /c:\"JTS Windows Companion temporary setup v1\" \"%JTS_TEMP_SETUP_CLEANUP_ROOT%\\.jts-temporary-setup-v1\" >nul 2>nul",
            lines);
    }
}
