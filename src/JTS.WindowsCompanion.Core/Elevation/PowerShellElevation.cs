using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using JTS.WindowsCompanion.Files;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Shell;

namespace JTS.WindowsCompanion.Elevation;

[JsonConverter(typeof(JsonStringEnumConverter<ElevationScopeAccess>))]
public enum ElevationScopeAccess
{
    Read,
    ReadWrite,
}

public sealed record ElevationDataScope(
    string RootId,
    string RelativePath,
    ElevationScopeAccess Access);

public sealed record PowerShellElevationRequest(
    ShellExecutionRequest Execution,
    int DurationMilliseconds,
    IReadOnlyList<ElevationDataScope> DataScopes);

public sealed record ResolvedElevationDataScope(
    string RootId,
    string FullPath,
    ElevationScopeAccess Access);

public sealed record ElevatedPowerShellActionDescriptor(
    string ActionId,
    string Script,
    string WorkingDirectory,
    int TimeoutMilliseconds,
    int MaximumOutputBytes,
    IReadOnlyDictionary<string, string> Environment,
    IReadOnlyList<ResolvedElevationDataScope> DataScopes)
{
    public byte[] CanonicalPayload => ElevationPayloadCodec.Serialize(this);

    public string PayloadSha256 => Convert.ToHexString(SHA256.HashData(CanonicalPayload));
}

public sealed record ElevatedShellExecutionCommand(
    Guid LeaseId,
    string ActionId,
    ElevatedPowerShellActionDescriptor Action);

public interface IElevationConsentPrompt
{
    ValueTask<bool> ConfirmAsync(
        ElevatedPowerShellActionDescriptor action,
        TimeSpan duration,
        CancellationToken cancellationToken);
}

public interface IElevationBrokerClient : IAsyncDisposable
{
    bool IsConfigured { get; }

    int ActiveLeaseCount { get; }

    ValueTask<ElevationLease> RequestAsync(
        PowerShellElevationRequest request,
        CancellationToken cancellationToken);

    ValueTask<ShellExecutionResult> ExecuteAsync(
        ShellExecutionRequest request,
        CancellationToken cancellationToken);

    ValueTask<ElevationLease> GetStatusAsync(Guid leaseId, CancellationToken cancellationToken);

    ValueTask ReleaseAsync(Guid leaseId, CancellationToken cancellationToken);
}

public sealed class UnavailableElevationBrokerClient : IElevationBrokerClient
{
    public static UnavailableElevationBrokerClient Instance { get; } = new();

    private UnavailableElevationBrokerClient()
    {
    }

    public bool IsConfigured => false;

    public int ActiveLeaseCount => 0;

    public ValueTask<ElevationLease> RequestAsync(
        PowerShellElevationRequest request,
        CancellationToken cancellationToken) =>
        ValueTask.FromException<ElevationLease>(NotConfigured());

    public ValueTask<ShellExecutionResult> ExecuteAsync(
        ShellExecutionRequest request,
        CancellationToken cancellationToken) =>
        ValueTask.FromException<ShellExecutionResult>(NotConfigured());

    public ValueTask<ElevationLease> GetStatusAsync(Guid leaseId, CancellationToken cancellationToken) =>
        ValueTask.FromException<ElevationLease>(NotConfigured());

    public ValueTask ReleaseAsync(Guid leaseId, CancellationToken cancellationToken) =>
        ValueTask.FromException(NotConfigured());

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    private static CompanionProtocolException NotConfigured() => new(
        "UAC_BROKER_REQUIRED",
        "Elevation requires the installed, release-verified JTS interactive UAC broker.");
}

public sealed class ElevationActionBuilder
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

    public ElevationActionBuilder(FileSandbox sandbox)
    {
        _sandbox = sandbox ?? throw new ArgumentNullException(nameof(sandbox));
    }

    public (ElevatedPowerShellActionDescriptor Action, TimeSpan Duration) Build(PowerShellElevationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var execution = request.Execution ?? throw new ArgumentException("An elevated shell request is required.", nameof(request));
        if (!execution.RequiresElevation
            || execution.ElevationLeaseId is not null
            || execution.ElevationActionId is not null
            || string.IsNullOrWhiteSpace(execution.Script)
            || execution.Script.Length > 64 * 1024
            || execution.Script.IndexOf('\0') >= 0
            || execution.TimeoutMilliseconds is < 100 or > 15 * 60 * 1000
            || execution.MaximumOutputBytes is < 1024 or > 128 * 1024)
        {
            throw new ArgumentException("The elevated PowerShell request is outside the permitted bounds.", nameof(request));
        }

        var duration = TimeSpan.FromMilliseconds(request.DurationMilliseconds);
        if (duration <= TimeSpan.Zero || duration > ElevationLeaseManager.MaximumDuration)
        {
            throw new ArgumentException("Elevation leases must be between 1 ms and 15 minutes.", nameof(request));
        }

        var environment = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in execution.Environment ?? new Dictionary<string, string>())
        {
            if (string.IsNullOrWhiteSpace(pair.Key)
                || pair.Key.Length > 128
                || pair.Value.Length > 4096
                || pair.Key.IndexOf('\0') >= 0
                || pair.Value.IndexOf('\0') >= 0
                || SecretMarkers.Any(marker => pair.Key.Contains(marker, StringComparison.OrdinalIgnoreCase)))
            {
                throw new ArgumentException("The requested environment contains a prohibited name or value.", nameof(request));
            }

            environment.Add(pair.Key, pair.Value);
        }

        var workingDirectory = _sandbox.Resolve(execution.RootId, execution.WorkingDirectory);
        if (!Directory.Exists(workingDirectory.FullPath))
        {
            throw new ArgumentException("The elevated shell working directory does not exist.", nameof(request));
        }

        if (request.DataScopes is null || request.DataScopes.Count is < 1 or > 16)
        {
            throw new ArgumentException("One to sixteen explicit data scopes are required.", nameof(request));
        }

        var scopes = request.DataScopes
            .Select(ResolveScope)
            .OrderBy(scope => scope.RootId, StringComparer.Ordinal)
            .ThenBy(scope => scope.FullPath, StringComparer.Ordinal)
            .ThenBy(scope => scope.Access)
            .ToArray();
        if (!scopes.Any(scope => Contains(scope.FullPath, workingDirectory.FullPath)))
        {
            throw new UnauthorizedAccessException("The working directory is outside the approved elevation data scopes.");
        }

        return (new ElevatedPowerShellActionDescriptor(
            $"powershell-{Guid.NewGuid():N}",
            execution.Script,
            workingDirectory.FullPath,
            execution.TimeoutMilliseconds,
            execution.MaximumOutputBytes,
            environment,
            scopes), duration);
    }

    public ElevatedPowerShellActionDescriptor RebuildForExecution(
        ShellExecutionRequest request,
        ElevatedPowerShellActionDescriptor approved)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(approved);
        if (!request.RequiresElevation
            || request.ElevationLeaseId is null
            || string.IsNullOrWhiteSpace(request.ElevationActionId)
            || request.ElevationActionId != approved.ActionId)
        {
            throw new UnauthorizedAccessException("An exact elevation lease and action ID are required.");
        }

        var rebuilt = Build(new PowerShellElevationRequest(
            request with { ElevationLeaseId = null, ElevationActionId = null },
            1,
            approved.DataScopes.Select(scope => new ElevationDataScope(
                scope.RootId,
                RelativeScopePath(scope),
                scope.Access)).ToArray())).Action with
        {
            ActionId = approved.ActionId,
        };
        if (!CryptographicOperations.FixedTimeEquals(rebuilt.CanonicalPayload, approved.CanonicalPayload))
        {
            throw new UnauthorizedAccessException("The elevated shell request does not match the approved action.");
        }

        return rebuilt;
    }

    private ResolvedElevationDataScope ResolveScope(ElevationDataScope scope)
    {
        if (scope is null
            || string.IsNullOrWhiteSpace(scope.RootId)
            || scope.RootId.IndexOf('\0') >= 0
            || string.IsNullOrWhiteSpace(scope.RelativePath)
            || scope.RelativePath.IndexOf('\0') >= 0)
        {
            throw new ArgumentException("Elevation data scopes require a root and relative path.");
        }

        var root = _sandbox.Roots.SingleOrDefault(candidate => candidate.Id == scope.RootId)
            ?? throw new UnauthorizedAccessException("The elevation data-scope root is not configured.");
        if (root.ReadOnly && scope.Access == ElevationScopeAccess.ReadWrite)
        {
            throw new UnauthorizedAccessException("A read-only root cannot be elevated for writes.");
        }

        var fullPath = scope.RelativePath == "."
            ? root.Path
            : _sandbox.Resolve(scope.RootId, scope.RelativePath).FullPath;
        if (!Directory.Exists(fullPath))
        {
            throw new UnauthorizedAccessException("Elevation data scopes must resolve to existing directories.");
        }

        return new ResolvedElevationDataScope(scope.RootId, fullPath, scope.Access);
    }

    private string RelativeScopePath(ResolvedElevationDataScope scope)
    {
        var root = _sandbox.Roots.Single(candidate => candidate.Id == scope.RootId);
        return string.Equals(root.Path, scope.FullPath, PathComparison())
            ? "."
            : Path.GetRelativePath(root.Path, scope.FullPath);
    }

    private static bool Contains(string parent, string candidate)
    {
        var comparison = PathComparison();
        if (string.Equals(parent, candidate, comparison))
        {
            return true;
        }

        var prefix = parent.EndsWith(Path.DirectorySeparatorChar)
            ? parent
            : parent + Path.DirectorySeparatorChar;
        return candidate.StartsWith(prefix, comparison);
    }

    private static StringComparison PathComparison() =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
}

public static class ElevationPayloadCodec
{
    public static byte[] Serialize(ElevatedPowerShellActionDescriptor action)
    {
        ArgumentNullException.ThrowIfNull(action);
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = false }))
        {
            writer.WriteStartObject();
            writer.WriteString("script", action.Script);
            writer.WriteString("workingDirectory", action.WorkingDirectory);
            writer.WriteNumber("timeoutMilliseconds", action.TimeoutMilliseconds);
            writer.WriteNumber("maximumOutputBytes", action.MaximumOutputBytes);
            writer.WriteStartObject("environment");
            foreach (var pair in action.Environment.OrderBy(pair => pair.Key, StringComparer.Ordinal))
            {
                writer.WriteString(pair.Key, pair.Value);
            }

            writer.WriteEndObject();
            writer.WriteStartArray("dataScopes");
            foreach (var scope in action.DataScopes
                         .OrderBy(scope => scope.RootId, StringComparer.Ordinal)
                         .ThenBy(scope => scope.FullPath, StringComparer.Ordinal)
                         .ThenBy(scope => scope.Access))
            {
                writer.WriteStartObject();
                writer.WriteString("rootId", scope.RootId);
                writer.WriteString("fullPath", scope.FullPath);
                writer.WriteString("access", scope.Access.ToString());
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }
}

public enum ElevationBrokerMessageKind
{
    Hello,
    OpenLease,
    LeaseOpened,
    Execute,
    ExecutionResult,
    Status,
    LeaseStatus,
    Release,
    Released,
    Error,
}

public sealed record ElevationBrokerMessage(
    int Version,
    Guid MessageId,
    ElevationBrokerMessageKind Kind,
    string Nonce,
    JsonElement Payload);

public sealed record ElevationBrokerOpenLease(
    ElevatedPowerShellActionDescriptor Action,
    int DurationMilliseconds);

public sealed record ElevationBrokerExecute(
    Guid LeaseId,
    string ActionId,
    ElevatedPowerShellActionDescriptor Action);

public sealed record ElevationBrokerLeaseId(Guid LeaseId);

public sealed record ElevationBrokerError(string Code, string Message);

public static class LocalIpcJsonCodec
{
    public const int MaximumPayloadBytes = 1024 * 1024;

    public static async ValueTask WriteAsync<T>(
        Stream stream,
        T value,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var payload = JsonSerializer.SerializeToUtf8Bytes(value, ControlMessageSerializer.Options);
        if (payload.Length is <= 0 or > MaximumPayloadBytes)
        {
            throw new InvalidDataException("The local IPC payload exceeds its bound.");
        }

        var header = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(header, payload.Length);
        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public static async ValueTask<T> ReadAsync<T>(Stream stream, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var header = new byte[4];
        await ReadExactlyAsync(stream, header, cancellationToken).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32BigEndian(header);
        if (length is <= 0 or > MaximumPayloadBytes)
        {
            throw new InvalidDataException("The local IPC frame length is invalid.");
        }

        var payload = new byte[length];
        await ReadExactlyAsync(stream, payload, cancellationToken).ConfigureAwait(false);
        return JsonSerializer.Deserialize<T>(payload, ControlMessageSerializer.Options)
            ?? throw new InvalidDataException("The local IPC payload is invalid.");
    }

    private static async ValueTask ReadExactlyAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[offset..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("The local IPC stream closed unexpectedly.");
            }

            offset += read;
        }
    }
}
