using System.ComponentModel;
using System.Diagnostics;
using System.Text;

namespace JTS.WindowsCompanion.Setup;

internal static class TemporarySetupCleanupScheduler
{
    internal const int MaximumCleanupAttempts = 120;

    private const string TemporaryDirectoryPrefix = "JTS-Windows-Companion-Setup-";
    private const string CleanupVariable = "JTS_TEMP_SETUP_CLEANUP_ROOT";
    private const string CleanupAttemptsVariable = "JTS_TEMP_SETUP_CLEANUP_ATTEMPTS";
    private const string CleanupValidatedVariable = "JTS_TEMP_SETUP_CLEANUP_VALIDATED";
    private const string SystemDirectoryVariable = "JTS_TEMP_SETUP_SYSTEM_DIRECTORY";
    private const string OwnershipMarkerName = ".jts-temporary-setup-v1";
    private const string OwnershipMarkerLine = "JTS Windows Companion temporary setup v1";
    private const string OwnershipMarkerContents = OwnershipMarkerLine + "\n";
    internal const string LaunchSentinelName = ".jts-temporary-setup-launching-v1";

    public static PreparedTemporarySetupLaunch PrepareTemporaryLaunch()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Detached Setup cleanup is available only on Windows.");
        }

        var root = CreateTemporaryRoot();
        FileStream? launchSentinel = null;
        try
        {
            launchSentinel = CreateLaunchSentinel(root);
            ScheduleCleanup(
                root,
                Path.Combine(root, InstallerLayout.SetupFileName));
            return new PreparedTemporarySetupLaunch(root, launchSentinel);
        }
        catch
        {
            launchSentinel?.Dispose();
            TryDeleteTemporaryRoot(root);
            throw;
        }
    }

    public static string CreateTemporaryRoot()
    {
        var root = Path.Combine(
            Path.GetFullPath(Path.GetTempPath()),
            TemporaryDirectoryPrefix + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        File.WriteAllText(
            Path.Combine(root, OwnershipMarkerName),
            OwnershipMarkerContents,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        return root;
    }

    internal static FileStream CreateLaunchSentinel(string temporaryRoot)
    {
        ValidateOwnedTemporaryRoot(
            temporaryRoot,
            Path.Combine(temporaryRoot, InstallerLayout.SetupFileName));
        var sentinelPath = Path.Combine(temporaryRoot, LaunchSentinelName);
        // FileShare.None is the liveness handshake: the helper's delete cannot
        // succeed until this process starts the child or is terminated by Windows.
        var sentinel = new FileStream(
            sentinelPath,
            FileMode.CreateNew,
            FileAccess.ReadWrite,
            FileShare.None,
            bufferSize: 1,
            FileOptions.WriteThrough);
        try
        {
            sentinel.WriteByte(1);
            sentinel.Flush(flushToDisk: true);
            return sentinel;
        }
        catch
        {
            sentinel.Dispose();
            throw;
        }
    }

    public static string? IdentifyTemporaryRoot(string executablePath)
    {
        var executable = Path.GetFullPath(executablePath);
        if (!string.Equals(
                Path.GetFileName(executable),
                InstallerLayout.SetupFileName,
                StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var root = Directory.GetParent(executable)?.FullName;
        if (root is null || !IsGeneratedTemporaryRoot(root))
        {
            return null;
        }
        return root;
    }

    public static void TryScheduleForCurrentProcess(string executablePath)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
        var temporaryRoot = IdentifyTemporaryRoot(executablePath);
        if (temporaryRoot is null)
        {
            return;
        }

        try
        {
            ScheduleCleanup(temporaryRoot, executablePath);
        }
        catch (Exception exception) when (
            exception is IOException or
            UnauthorizedAccessException or
            InvalidDataException or
            InvalidOperationException or
            Win32Exception)
        {
            // The parent-scheduled helper remains authoritative when this is a child.
        }
    }

    internal static IReadOnlyList<string> CreateCleanupScriptLines() =>
    [
        "@echo off",
        "setlocal DisableDelayedExpansion",
        $"set \"{CleanupAttemptsVariable}=0\"",
        $"set \"{CleanupValidatedVariable}=0\"",
        ":retry",
        $"del /f /q \"%{CleanupVariable}%\\{LaunchSentinelName}\" >nul 2>nul",
        $"if exist \"%{CleanupVariable}%\\{LaunchSentinelName}\" goto wait",
        $"if not exist \"%{CleanupVariable}%\\\" goto cleaned",
        $"if \"%{CleanupValidatedVariable}%\"==\"1\" goto remove",
        $"if not exist \"%{CleanupVariable}%\\{OwnershipMarkerName}\" goto exhausted",
        $"for %%I in (\"%{CleanupVariable}%\\{OwnershipMarkerName}\") do if not \"%%~zI\"==\"{Encoding.UTF8.GetByteCount(OwnershipMarkerContents)}\" goto exhausted",
        $"\"%{SystemDirectoryVariable}%\\findstr.exe\" /x /l /c:\"{OwnershipMarkerLine}\" \"%{CleanupVariable}%\\{OwnershipMarkerName}\" >nul 2>nul",
        "if errorlevel 1 goto exhausted",
        $"set \"{CleanupValidatedVariable}=1\"",
        ":remove",
        $"rmdir /s /q \"%{CleanupVariable}%\" >nul 2>nul",
        $"if not exist \"%{CleanupVariable}%\\\" goto cleaned",
        ":wait",
        $"set /a {CleanupAttemptsVariable}+=1 >nul",
        $"if %{CleanupAttemptsVariable}% GEQ {MaximumCleanupAttempts} goto exhausted",
        $"\"%{SystemDirectoryVariable}%\\ping.exe\" 127.0.0.1 -n 2 >nul",
        "goto retry",
        ":cleaned",
        "del /f /q \"%~f0\" >nul 2>nul",
        "exit /b 0",
        ":exhausted",
        "del /f /q \"%~f0\" >nul 2>nul",
        "exit /b 1",
    ];

    private static void ScheduleCleanup(
        string temporaryRoot,
        string executablePath)
    {
        ValidateOwnedTemporaryRoot(temporaryRoot, executablePath);
        var temporaryParent = Directory.GetParent(temporaryRoot)?.FullName
            ?? throw new InvalidDataException("The temporary Setup directory has no parent.");
        var systemDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System);
        if (string.IsNullOrWhiteSpace(systemDirectory))
        {
            throw new FileNotFoundException(
                "The Windows system directory is unavailable for temporary Setup cleanup.");
        }
        systemDirectory = Path.GetFullPath(systemDirectory);
        var commandInterpreter = Path.Combine(systemDirectory, "cmd.exe");
        if (!File.Exists(commandInterpreter) ||
            (File.GetAttributes(commandInterpreter) & FileAttributes.ReparsePoint) != 0)
        {
            throw new FileNotFoundException(
                "The Windows command interpreter is unavailable for temporary Setup cleanup.");
        }

        string? scriptPath = Path.Combine(
            temporaryParent,
            $".jts-setup-cleanup-{Guid.NewGuid():N}.cmd");
        try
        {
            using (var script = new FileStream(
                       scriptPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.Read,
                       bufferSize: 4 * 1024,
                       FileOptions.WriteThrough))
            using (var writer = new StreamWriter(
                       script,
                       new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
                       bufferSize: 4 * 1024,
                       leaveOpen: false))
            {
                writer.NewLine = "\r\n";
                foreach (var line in CreateCleanupScriptLines())
                {
                    writer.WriteLine(line);
                }
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = commandInterpreter,
                WorkingDirectory = temporaryParent,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            startInfo.ArgumentList.Add("/d");
            startInfo.ArgumentList.Add("/q");
            startInfo.ArgumentList.Add("/c");
            startInfo.ArgumentList.Add(scriptPath);
            startInfo.Environment[CleanupVariable] = temporaryRoot;
            startInfo.Environment[SystemDirectoryVariable] = systemDirectory;
            using var cleanup = Process.Start(startInfo)
                ?? throw new InvalidOperationException(
                    "The temporary Setup cleanup process could not start.");
            scriptPath = null;
        }
        finally
        {
            TryDeleteScript(scriptPath);
        }
    }

    private static bool IsGeneratedTemporaryRoot(string candidate)
    {
        var normalized = Path.GetFullPath(candidate);
        var temporaryParent = Path.GetFullPath(Path.GetTempPath())
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var parent = Directory.GetParent(normalized)?.FullName;
        var name = Path.GetFileName(normalized);
        return string.Equals(parent, temporaryParent, StringComparison.OrdinalIgnoreCase) &&
               name.StartsWith(TemporaryDirectoryPrefix, StringComparison.Ordinal) &&
               Guid.TryParseExact(name[TemporaryDirectoryPrefix.Length..], "N", out _);
    }

    private static void ValidateOwnedTemporaryRoot(
        string temporaryRoot,
        string executablePath)
    {
        if (!IsGeneratedTemporaryRoot(temporaryRoot) ||
            !Directory.Exists(temporaryRoot) ||
            (File.GetAttributes(temporaryRoot) & FileAttributes.ReparsePoint) != 0)
        {
            throw new UnauthorizedAccessException(
                "The temporary Setup directory name is invalid, missing, or is a reparse point.");
        }

        var markerPath = Path.Combine(temporaryRoot, OwnershipMarkerName);
        if (!File.Exists(markerPath) ||
            (File.GetAttributes(markerPath) & FileAttributes.ReparsePoint) != 0 ||
            !string.Equals(
                File.ReadAllText(markerPath, Encoding.UTF8),
                OwnershipMarkerContents,
                StringComparison.Ordinal))
        {
            throw new UnauthorizedAccessException(
                "The temporary Setup directory ownership marker is invalid.");
        }

        var expectedExecutable = Path.Combine(temporaryRoot, InstallerLayout.SetupFileName);
        if (!string.Equals(
                Path.GetFullPath(executablePath),
                expectedExecutable,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException(
                "The temporary Setup executable path is invalid.");
        }
        if (File.Exists(expectedExecutable) &&
            (File.GetAttributes(expectedExecutable) & FileAttributes.ReparsePoint) != 0)
        {
            throw new UnauthorizedAccessException(
                "The temporary Setup executable is a reparse point.");
        }
        var launchSentinel = Path.Combine(temporaryRoot, LaunchSentinelName);
        if (File.Exists(launchSentinel) &&
            (File.GetAttributes(launchSentinel) & FileAttributes.ReparsePoint) != 0)
        {
            throw new UnauthorizedAccessException(
                "The temporary Setup launch sentinel is a reparse point.");
        }
        var allowedEntries = new HashSet<string>(
            new[]
            {
                OwnershipMarkerName,
                InstallerLayout.SetupFileName,
                LaunchSentinelName,
            },
            StringComparer.OrdinalIgnoreCase);
        if (Directory.EnumerateFileSystemEntries(temporaryRoot).Any(
                entry => !allowedEntries.Contains(Path.GetFileName(entry))))
        {
            throw new UnauthorizedAccessException(
                "The temporary Setup directory contains an unexpected entry.");
        }
    }

    private static void TryDeleteTemporaryRoot(string path)
    {
        try
        {
            InstallerLayout.DeleteDirectoryWithoutFollowingLinks(path);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            // A cleanup helper may already own deletion, or a later residue pass can retry.
        }
    }

    private static void TryDeleteScript(string? path)
    {
        try
        {
            if (path is not null && File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            // A later temporary-file cleanup pass may remove an abandoned helper script.
        }
    }
}

internal sealed class PreparedTemporarySetupLaunch : IDisposable
{
    private FileStream? _launchSentinel;

    public PreparedTemporarySetupLaunch(
        string rootPath,
        FileStream launchSentinel)
    {
        RootPath = rootPath;
        _launchSentinel = launchSentinel;
    }

    public string RootPath { get; }

    public void ReleaseForCleanup()
    {
        Interlocked.Exchange(ref _launchSentinel, null)?.Dispose();
    }

    public void Dispose()
    {
        ReleaseForCleanup();
    }
}
