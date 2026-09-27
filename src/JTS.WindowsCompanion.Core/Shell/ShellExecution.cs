using System.Diagnostics;
using System.Text;
using JTS.WindowsCompanion.Files;
using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.Shell;

public sealed record ShellExecutionRequest(
    string Script,
    string RootId,
    string WorkingDirectory,
    int TimeoutMilliseconds = 60_000,
    int MaximumOutputBytes = 128 * 1024,
    IReadOnlyDictionary<string, string>? Environment = null,
    bool RequiresElevation = false,
    Guid? ElevationLeaseId = null,
    string? ElevationActionId = null);

public sealed record ShellExecutionResult(
    int ExitCode,
    string StandardOutput,
    string StandardError,
    bool TimedOut,
    bool OutputTruncated,
    long DurationMilliseconds);

public sealed class CurrentUserShellPolicy
{
    private static readonly string[] SecretMarkers =
    [
        "PASSWORD",
        "PASSWD",
        "SECRET",
        "TOKEN",
        "PRIVATE_KEY",
        "ACCESS_KEY",
        "CREDENTIAL",
    ];

    private readonly FileSandbox _sandbox;

    public CurrentUserShellPolicy(FileSandbox sandbox)
    {
        _sandbox = sandbox ?? throw new ArgumentNullException(nameof(sandbox));
    }

    public SandboxedPath Validate(ShellExecutionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.RequiresElevation)
        {
            throw new UnauthorizedAccessException("Current-user shell execution cannot request elevation.");
        }

        if (request.ElevationLeaseId is not null || request.ElevationActionId is not null)
        {
            throw new UnauthorizedAccessException("Elevation lease fields are not accepted by the current-user shell.");
        }

        if (string.IsNullOrWhiteSpace(request.Script) || request.Script.Length > 64 * 1024)
        {
            throw new ArgumentException("PowerShell scripts must be 1 to 65,536 characters.", nameof(request));
        }

        if (request.TimeoutMilliseconds is < 100 or > 15 * 60 * 1000)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Shell timeouts must be between 100 ms and 15 minutes.");
        }

        if (request.MaximumOutputBytes is < 1024 or > 128 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Shell output limits must be between 1 KiB and 128 KiB.");
        }

        foreach (var pair in request.Environment ?? new Dictionary<string, string>())
        {
            if (string.IsNullOrWhiteSpace(pair.Key)
                || pair.Key.Length > 128
                || pair.Value.Length > 4096
                || SecretMarkers.Any(marker => pair.Key.Contains(marker, StringComparison.OrdinalIgnoreCase)))
            {
                throw new ArgumentException("The requested environment contains a prohibited name or value.", nameof(request));
            }
        }

        var workingDirectory = request.WorkingDirectory == "."
            ? _sandbox.ResolveRootDirectory(request.RootId)
            : _sandbox.Resolve(request.RootId, request.WorkingDirectory);
        if (!Directory.Exists(workingDirectory.FullPath))
        {
            throw new ArgumentException("The shell working directory does not exist.", nameof(request));
        }

        return workingDirectory;
    }
}

public sealed class CurrentUserPowerShellExecutor
{
    private static readonly string[] SafeInheritedEnvironment =
    [
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
        "PATH",
        "PATHEXT",
        "COMSPEC",
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
    ];

    private readonly CurrentUserShellPolicy _policy;
    private readonly ISecurityEventSink _events;

    public CurrentUserPowerShellExecutor(CurrentUserShellPolicy policy, ISecurityEventSink? events = null)
    {
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _events = events ?? NullSecurityEventSink.Instance;
    }

    public async ValueTask<ShellExecutionResult> ExecuteAsync(
        ShellExecutionRequest request,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("PowerShell execution is available only on Windows.");
        }

        var workingDirectory = _policy.Validate(request);
        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            WorkingDirectory = workingDirectory.FullPath,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        PowerShellUtf8LaunchPlan.Configure(startInfo);
        RestrictEnvironment(startInfo, request.Environment);

        using var process = new Process { StartInfo = startInfo };
        var stopwatch = Stopwatch.StartNew();
        if (!process.Start())
        {
            throw new InvalidOperationException("PowerShell could not be started.");
        }

        var standardInput = PowerShellUtf8LaunchPlan.CreateStandardInput(request.Script);
        await process.StandardInput.WriteAsync(standardInput.AsMemory(), cancellationToken).ConfigureAwait(false);
        await process.StandardInput.DisposeAsync().ConfigureAwait(false);

        var outputTask = ReadBoundedAsync(process.StandardOutput, request.MaximumOutputBytes / 2, cancellationToken);
        var errorTask = ReadBoundedAsync(process.StandardError, request.MaximumOutputBytes / 2, cancellationToken);
        using var timeout = new CancellationTokenSource(request.TimeoutMilliseconds);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);
        var timedOut = false;
        try
        {
            await process.WaitForExitAsync(linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            timedOut = true;
            TryKill(process);
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            throw;
        }

        var output = await outputTask.ConfigureAwait(false);
        var error = await errorTask.ConfigureAwait(false);
        stopwatch.Stop();
        var result = new ShellExecutionResult(
            process.HasExited ? process.ExitCode : -1,
            output.Text,
            error.Text,
            timedOut,
            output.Truncated || error.Truncated,
            stopwatch.ElapsedMilliseconds);
        _events.Record(new SecurityEvent(
            DateTimeOffset.UtcNow,
            "shell",
            "execute",
            result.ExitCode == 0 && !timedOut ? "success" : "failure",
            timedOut ? "TIMEOUT" : null));
        return result;
    }

    private static void RestrictEnvironment(
        ProcessStartInfo startInfo,
        IReadOnlyDictionary<string, string>? requestedEnvironment)
    {
        var inherited = SafeInheritedEnvironment
            .Select(name => (Name: name, Value: Environment.GetEnvironmentVariable(name)))
            .Where(pair => pair.Value is not null)
            .ToArray();
        startInfo.Environment.Clear();
        foreach (var pair in inherited)
        {
            startInfo.Environment[pair.Name] = pair.Value!;
        }

        foreach (var pair in requestedEnvironment ?? new Dictionary<string, string>())
        {
            startInfo.Environment[pair.Key] = pair.Value;
        }
    }

    private static async Task<(string Text, bool Truncated)> ReadBoundedAsync(
        StreamReader reader,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        var builder = new StringBuilder(Math.Min(maximumBytes, 64 * 1024));
        var buffer = new char[4096];
        var byteCount = 0;
        var truncated = false;
        while (true)
        {
            var count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (count == 0)
            {
                break;
            }

            var accepted = count;
            while (accepted > 0 && byteCount + Encoding.UTF8.GetByteCount(buffer, 0, accepted) > maximumBytes)
            {
                accepted--;
            }

            if (accepted > 0)
            {
                builder.Append(buffer, 0, accepted);
                byteCount += Encoding.UTF8.GetByteCount(buffer, 0, accepted);
            }

            if (accepted < count)
            {
                truncated = true;
            }
        }

        return (builder.ToString(), truncated);
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(5_000);
            }
        }
        catch (InvalidOperationException)
        {
        }
    }
}
