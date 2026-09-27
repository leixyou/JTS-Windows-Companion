using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.Managed;

public sealed record InstalledManagedProvider(
    WindowsTaskProviderManifest Manifest,
    string HandlerExecutablePath);

public interface IInstalledHandlerVerifier
{
    void Verify(string executablePath, string expectedSha256);
}

public sealed class Sha256InstalledHandlerVerifier : IInstalledHandlerVerifier
{
    public void Verify(string executablePath, string expectedSha256)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        if (expectedSha256.Length != 64 || !expectedSha256.All(char.IsAsciiHexDigit))
        {
            throw new ArgumentException("The installed handler digest is invalid.", nameof(expectedSha256));
        }

        using var stream = new FileStream(
            executablePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.SequentialScan);
        var actual = Convert.ToHexString(SHA256.HashData(stream));
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(actual),
                Encoding.ASCII.GetBytes(expectedSha256.ToUpperInvariant())))
        {
            throw new UnauthorizedAccessException("The installed managed handler digest does not match its manifest.");
        }
    }
}

public sealed class InstalledManagedProviderStore
{
    private readonly IReadOnlyDictionary<string, InstalledManagedProvider> _providers;

    public InstalledManagedProviderStore(
        string manifestDirectory,
        string handlerDirectory,
        IInstalledHandlerVerifier? verifier = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(manifestDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(handlerDirectory);
        var manifests = Path.GetFullPath(manifestDirectory);
        var handlers = Path.GetFullPath(handlerDirectory);
        RejectDirectory(manifests);
        RejectDirectory(handlers);
        verifier ??= new Sha256InstalledHandlerVerifier();

        var loaded = new Dictionary<string, InstalledManagedProvider>(StringComparer.Ordinal);
        foreach (var file in Directory.EnumerateFiles(manifests, "*.json", SearchOption.TopDirectoryOnly)
                     .OrderBy(path => path, StringComparer.Ordinal))
        {
            if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0)
            {
                throw new UnauthorizedAccessException("Managed manifest links are not accepted.");
            }

            var bytes = File.ReadAllBytes(file);
            if (bytes.Length is <= 0 or > 256 * 1024)
            {
                throw new InvalidDataException("A managed manifest exceeds its size bound.");
            }

            var document = JsonSerializer.Deserialize<InstalledProviderDocument>(bytes, ControlMessageSerializer.Options)
                ?? throw new InvalidDataException("A managed provider manifest is invalid.");
            var handlerPath = ResolveInstalledHandler(handlers, document.HandlerExecutable);
            verifier.Verify(handlerPath, document.HandlerSha256);
            var manifest = document.ToManifest();
            _ = new ManagedServicePolicy([manifest]);
            if (!loaded.TryAdd(manifest.ProviderId, new InstalledManagedProvider(manifest, handlerPath)))
            {
                throw new InvalidDataException("Installed managed provider IDs must be unique.");
            }
        }

        _providers = loaded;
    }

    public IReadOnlyCollection<InstalledManagedProvider> Providers => _providers.Values.ToArray();

    public InstalledManagedProvider Get(string providerId) =>
        _providers.TryGetValue(providerId, out var provider)
            ? provider
            : throw new UnauthorizedAccessException("The managed provider is not installed.");

    private static string ResolveInstalledHandler(string handlerDirectory, string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath)
            || Path.IsPathRooted(relativePath)
            || relativePath.IndexOf('\0') >= 0
            || relativePath.Replace('\\', '/').Split('/').Any(segment => segment is "" or "." or ".."))
        {
            throw new UnauthorizedAccessException("The managed handler path is invalid.");
        }

        var fullPath = Path.GetFullPath(Path.Combine(handlerDirectory, relativePath));
        var prefix = handlerDirectory.EndsWith(Path.DirectorySeparatorChar)
            ? handlerDirectory
            : handlerDirectory + Path.DirectorySeparatorChar;
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (!fullPath.StartsWith(prefix, comparison)
            || !File.Exists(fullPath)
            || HasReparseSegment(handlerDirectory, fullPath))
        {
            throw new UnauthorizedAccessException("The managed handler is outside the installed handler directory.");
        }

        return fullPath;
    }

    private static bool HasReparseSegment(string root, string path)
    {
        var current = root;
        foreach (var segment in Path.GetRelativePath(root, path)
                     .Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                return true;
            }
        }

        return false;
    }

    private static void RejectDirectory(string path)
    {
        if (!Directory.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new DirectoryNotFoundException("The installed managed provider directory is missing or unsafe.");
        }
    }

    private sealed record InstalledProviderDocument(
        string ProviderId,
        string Version,
        string HandlerExecutable,
        string HandlerSha256,
        IReadOnlyList<InstalledOperationDocument> Operations)
    {
        public WindowsTaskProviderManifest ToManifest() => new(
            ProviderId,
            Version,
            HandlerSha256,
            Operations.Select(operation => new ManagedOperationDefinition(
                operation.OperationId,
                new HashSet<string>(operation.AcceptedArguments, StringComparer.Ordinal),
                new HashSet<string>(operation.AllowedRootIds, StringComparer.Ordinal),
                TimeSpan.FromMilliseconds(operation.MaximumDurationMilliseconds))).ToArray());
    }

    private sealed record InstalledOperationDocument(
        string OperationId,
        IReadOnlyList<string> AcceptedArguments,
        IReadOnlyList<string> AllowedRootIds,
        int MaximumDurationMilliseconds);
}

public sealed record ManagedOperationExecutionResult(
    int ExitCode,
    string StandardOutput,
    string StandardError,
    bool TimedOut,
    bool OutputTruncated,
    long DurationMilliseconds);

public interface IManagedOperationExecutor
{
    ValueTask<ManagedOperationExecutionResult> ExecuteAsync(
        InstalledManagedProvider provider,
        AuthorizedManagedOperation operation,
        CancellationToken cancellationToken);
}

public sealed class FixedManagedOperationProcessExecutor : IManagedOperationExecutor
{
    private const int MaximumOutputBytes = 128 * 1024;
    private readonly IInstalledHandlerVerifier _verifier;
    private readonly ISecurityEventSink _events;

    public FixedManagedOperationProcessExecutor(
        IInstalledHandlerVerifier? verifier = null,
        ISecurityEventSink? events = null)
    {
        _verifier = verifier ?? new Sha256InstalledHandlerVerifier();
        _events = events ?? NullSecurityEventSink.Instance;
    }

    public async ValueTask<ManagedOperationExecutionResult> ExecuteAsync(
        InstalledManagedProvider provider,
        AuthorizedManagedOperation operation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(operation);
        using var handlerFileLock = new FileStream(
            provider.HandlerExecutablePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read);
        _verifier.Verify(provider.HandlerExecutablePath, provider.Manifest.HandlerAssemblySha256);
        var startInfo = new ProcessStartInfo
        {
            FileName = provider.HandlerExecutablePath,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        startInfo.ArgumentList.Add("--managed-operation");
        startInfo.ArgumentList.Add(operation.OperationId);
        RestrictEnvironment(startInfo);

        using var process = new Process { StartInfo = startInfo };
        var stopwatch = Stopwatch.StartNew();
        if (!process.Start())
        {
            throw new InvalidOperationException("The installed managed operation handler could not be started.");
        }

        var input = JsonSerializer.Serialize(new
        {
            providerId = operation.ProviderId,
            operationId = operation.OperationId,
            arguments = operation.Arguments,
            rootIds = operation.RootIds,
            timeoutMilliseconds = checked((int)operation.Timeout.TotalMilliseconds),
        }, ControlMessageSerializer.Options);
        await process.StandardInput.WriteAsync(input.AsMemory(), cancellationToken).ConfigureAwait(false);
        await process.StandardInput.DisposeAsync().ConfigureAwait(false);
        var outputTask = ReadBoundedAsync(process.StandardOutput, MaximumOutputBytes / 2, cancellationToken);
        var errorTask = ReadBoundedAsync(process.StandardError, MaximumOutputBytes / 2, cancellationToken);
        using var timeout = new CancellationTokenSource(operation.Timeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token, cancellationToken);
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
        var result = new ManagedOperationExecutionResult(
            process.HasExited ? process.ExitCode : -1,
            output.Text,
            error.Text,
            timedOut,
            output.Truncated || error.Truncated,
            stopwatch.ElapsedMilliseconds);
        _events.Record(new SecurityEvent(
            DateTimeOffset.UtcNow,
            "managed-service",
            operation.OperationId,
            result.ExitCode == 0 && !timedOut ? "success" : "failure",
            timedOut ? "TIMEOUT" : null));
        return result;
    }

    private static void RestrictEnvironment(ProcessStartInfo startInfo)
    {
        var systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
        var path = Environment.GetEnvironmentVariable("PATH");
        startInfo.Environment.Clear();
        if (systemRoot is not null)
        {
            startInfo.Environment["SystemRoot"] = systemRoot;
            startInfo.Environment["WINDIR"] = systemRoot;
        }

        if (path is not null)
        {
            startInfo.Environment["PATH"] = path;
        }
    }

    private static async Task<(string Text, bool Truncated)> ReadBoundedAsync(
        StreamReader reader,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        var builder = new StringBuilder();
        var buffer = new char[4096];
        var bytes = 0;
        var truncated = false;
        while (true)
        {
            var count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (count == 0)
            {
                break;
            }

            var accepted = count;
            while (accepted > 0 && bytes + Encoding.UTF8.GetByteCount(buffer, 0, accepted) > maximumBytes)
            {
                accepted--;
            }

            if (accepted > 0)
            {
                builder.Append(buffer, 0, accepted);
                bytes += Encoding.UTF8.GetByteCount(buffer, 0, accepted);
            }

            truncated |= accepted < count;
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
