using System.Diagnostics;
using System.Text;
using JTS.WindowsCompanion.Security;
using JTS.WindowsCompanion.Shell;

namespace JTS.WindowsCompanion.Elevation;

public interface IProcessElevationVerifier
{
    bool IsElevated { get; }
}

public sealed class ElevatedPowerShellExecutor
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

    private readonly IProcessElevationVerifier _elevationVerifier;
    private readonly IContainedProcessFactory _processFactory;
    private readonly TimeProvider _timeProvider;
    private readonly ISecurityEventSink _events;

    public ElevatedPowerShellExecutor(
        IProcessElevationVerifier elevationVerifier,
        ISecurityEventSink? events = null)
        : this(
            elevationVerifier,
            WindowsJobObjectProcessFactory.Instance,
            TimeProvider.System,
            events)
    {
    }

    internal ElevatedPowerShellExecutor(
        IProcessElevationVerifier elevationVerifier,
        IContainedProcessFactory processFactory,
        TimeProvider timeProvider,
        ISecurityEventSink? events = null)
    {
        _elevationVerifier = elevationVerifier ?? throw new ArgumentNullException(nameof(elevationVerifier));
        _processFactory = processFactory ?? throw new ArgumentNullException(nameof(processFactory));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _events = events ?? NullSecurityEventSink.Instance;
    }

    public async ValueTask<ShellExecutionResult> ExecuteAsync(
        ElevatedPowerShellActionDescriptor action,
        CancellationToken cancellationToken)
    {
        Validate(action);
        if (!_elevationVerifier.IsElevated)
        {
            throw new UnauthorizedAccessException("The UAC broker process is not elevated.");
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            WorkingDirectory = action.WorkingDirectory,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        PowerShellUtf8LaunchPlan.Configure(startInfo);
        RestrictEnvironment(startInfo, action.Environment);

        await using var process = _processFactory.Create(startInfo);
        var stopwatch = Stopwatch.StartNew();
        using var timeout = new CancellationTokenSource(
            TimeSpan.FromMilliseconds(action.TimeoutMilliseconds),
            _timeProvider);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);
        var output = new BoundedOutputCapture(action.MaximumOutputBytes / 2);
        var error = new BoundedOutputCapture(action.MaximumOutputBytes / 2);
        Task? outputTask = null;
        Task? errorTask = null;
        var timedOut = false;
        try
        {
            await process.StartAsync(linked.Token).ConfigureAwait(false);
            outputTask = output.ReadAsync(process.StandardOutput, linked.Token);
            errorTask = error.ReadAsync(process.StandardError, linked.Token);
            await process.WriteStandardInputAsync(action.Script.AsMemory(), linked.Token).ConfigureAwait(false);
            await process.WaitForExitAsync(linked.Token).ConfigureAwait(false);
            await Task.WhenAll(outputTask, errorTask).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            timedOut = timeout.IsCancellationRequested;
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            timedOut = true;
        }
        finally
        {
            if (!process.HasExited)
            {
                await process.TerminateAsync().ConfigureAwait(false);
            }

            if (outputTask is not null && errorTask is not null)
            {
                await Task.WhenAll(outputTask, errorTask).ConfigureAwait(false);
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        stopwatch.Stop();
        var result = new ShellExecutionResult(
            process.HasExited ? process.ExitCode : -1,
            output.Text,
            error.Text,
            timedOut,
            output.Truncated || error.Truncated,
            stopwatch.ElapsedMilliseconds);
        _events.Record(new SecurityEvent(
            _timeProvider.GetUtcNow(),
            "elevation",
            "powershell",
            result.ExitCode == 0 && !timedOut ? "success" : "failure",
            timedOut ? "TIMEOUT" : null));
        return result;
    }

    public static void Validate(ElevatedPowerShellActionDescriptor action)
    {
        ArgumentNullException.ThrowIfNull(action);
        if (string.IsNullOrWhiteSpace(action.ActionId)
            || action.ActionId.Length > 128
            || string.IsNullOrWhiteSpace(action.Script)
            || action.Script.Length > 64 * 1024
            || action.Script.IndexOf('\0') >= 0
            || string.IsNullOrWhiteSpace(action.WorkingDirectory)
            || !Path.IsPathFullyQualified(action.WorkingDirectory)
            || action.TimeoutMilliseconds is < 100 or > 15 * 60 * 1000
            || action.MaximumOutputBytes is < 1024 or > 128 * 1024
            || action.DataScopes.Count is < 1 or > 16
            || action.Environment.Any(pair =>
                string.IsNullOrWhiteSpace(pair.Key)
                || pair.Key.Length > 128
                || pair.Value.Length > 4096
                || pair.Key.IndexOf('\0') >= 0
                || pair.Value.IndexOf('\0') >= 0))
        {
            throw new ArgumentException("The elevated PowerShell action is invalid.", nameof(action));
        }

        var workingDirectory = Path.GetFullPath(action.WorkingDirectory);
        var containingScope = action.DataScopes.FirstOrDefault(scope => Contains(scope.FullPath, workingDirectory));
        if (!Directory.Exists(workingDirectory)
            || containingScope is null
            || HasReparseSegment(containingScope.FullPath, workingDirectory))
        {
            throw new UnauthorizedAccessException("The elevated PowerShell working directory is outside its approved data scopes.");
        }

        foreach (var scope in action.DataScopes)
        {
            if (string.IsNullOrWhiteSpace(scope.RootId)
                || string.IsNullOrWhiteSpace(scope.FullPath)
                || !Path.IsPathFullyQualified(scope.FullPath)
                || !Directory.Exists(scope.FullPath)
                || IsReparsePoint(scope.FullPath))
            {
                throw new UnauthorizedAccessException("An elevated data scope is invalid or no longer available.");
            }
        }
    }

    private static bool Contains(string parent, string candidate)
    {
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var normalizedParent = Path.GetFullPath(parent);
        var normalizedCandidate = Path.GetFullPath(candidate);
        if (string.Equals(normalizedParent, normalizedCandidate, comparison))
        {
            return true;
        }

        var prefix = normalizedParent.EndsWith(Path.DirectorySeparatorChar)
            ? normalizedParent
            : normalizedParent + Path.DirectorySeparatorChar;
        return normalizedCandidate.StartsWith(prefix, comparison);
    }

    private static bool IsReparsePoint(string path) =>
        (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;

    private static bool HasReparseSegment(string parent, string candidate)
    {
        var normalizedParent = Path.GetFullPath(parent);
        if (IsReparsePoint(normalizedParent))
        {
            return true;
        }

        var relative = Path.GetRelativePath(normalizedParent, Path.GetFullPath(candidate));
        var current = normalizedParent;
        foreach (var segment in relative.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if (IsReparsePoint(current))
            {
                return true;
            }
        }

        return false;
    }

    private static void RestrictEnvironment(
        ProcessStartInfo startInfo,
        IReadOnlyDictionary<string, string> requestedEnvironment)
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

        foreach (var pair in requestedEnvironment)
        {
            startInfo.Environment[pair.Key] = pair.Value;
        }
    }

    private sealed class BoundedOutputCapture
    {
        private readonly int _maximumBytes;
        private readonly StringBuilder _builder;
        private int _byteCount;

        public BoundedOutputCapture(int maximumBytes)
        {
            _maximumBytes = maximumBytes;
            _builder = new StringBuilder(Math.Min(maximumBytes, 64 * 1024));
        }

        public string Text => _builder.ToString();

        public bool Truncated { get; private set; }

        public async Task ReadAsync(TextReader reader, CancellationToken cancellationToken)
        {
            var buffer = new char[4096];
            try
            {
                while (true)
                {
                    var count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
                    if (count == 0)
                    {
                        return;
                    }

                    var accepted = count;
                    while (accepted > 0
                           && _byteCount + Encoding.UTF8.GetByteCount(buffer, 0, accepted) > _maximumBytes)
                    {
                        accepted--;
                    }

                    if (accepted > 0)
                    {
                        _builder.Append(buffer, 0, accepted);
                        _byteCount += Encoding.UTF8.GetByteCount(buffer, 0, accepted);
                    }

                    Truncated |= accepted < count;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }
        }
    }
}
