namespace JTS.WindowsCompanion.Managed;

public sealed record ManagedOperationDefinition(
    string OperationId,
    IReadOnlySet<string> AcceptedArguments,
    IReadOnlySet<string> AllowedRootIds,
    TimeSpan MaximumDuration);

public sealed record WindowsTaskProviderManifest(
    string ProviderId,
    string Version,
    string HandlerAssemblySha256,
    IReadOnlyList<ManagedOperationDefinition> Operations);

public sealed record ManagedOperationRequest(
    string ProviderId,
    string OperationId,
    IReadOnlyDictionary<string, string> Arguments,
    IReadOnlySet<string> RequestedRootIds,
    TimeSpan Timeout);

public sealed record AuthorizedManagedOperation(
    string ProviderId,
    string OperationId,
    IReadOnlyDictionary<string, string> Arguments,
    IReadOnlySet<string> RootIds,
    TimeSpan Timeout);

public sealed class ManagedServicePolicy
{
    private static readonly string[] ProhibitedArgumentMarkers =
    [
        "script",
        "shell",
        "powershell",
        "command",
        "executable",
        "arguments",
    ];

    private readonly Dictionary<string, WindowsTaskProviderManifest> _manifests;

    public ManagedServicePolicy(IEnumerable<WindowsTaskProviderManifest> manifests)
    {
        ArgumentNullException.ThrowIfNull(manifests);
        _manifests = new Dictionary<string, WindowsTaskProviderManifest>(StringComparer.Ordinal);
        foreach (var manifest in manifests)
        {
            ValidateManifest(manifest);
            if (!_manifests.TryAdd(manifest.ProviderId, manifest))
            {
                throw new ArgumentException("Managed provider IDs must be unique.", nameof(manifests));
            }
        }
    }

    public AuthorizedManagedOperation Authorize(ManagedOperationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!_manifests.TryGetValue(request.ProviderId, out var manifest))
        {
            throw new UnauthorizedAccessException("The managed provider is not installed.");
        }

        var operation = manifest.Operations.SingleOrDefault(candidate => candidate.OperationId == request.OperationId)
            ?? throw new UnauthorizedAccessException("The managed operation is not installed.");
        if (request.Timeout <= TimeSpan.Zero
            || request.Timeout > operation.MaximumDuration
            || request.Arguments.Count > 64
            || request.RequestedRootIds.Count > 32)
        {
            throw new UnauthorizedAccessException("The managed operation timeout exceeds its manifest.");
        }

        if (request.Arguments.Keys.Except(operation.AcceptedArguments, StringComparer.Ordinal).Any()
            || request.RequestedRootIds.Except(operation.AllowedRootIds, StringComparer.Ordinal).Any()
            || request.Arguments.Any(pair =>
                pair.Key.Length > 128
                || pair.Value.Length > 4096
                || (pair.Key.EndsWith("Path", StringComparison.OrdinalIgnoreCase) && !IsSafeRelativePath(pair.Value))))
        {
            throw new UnauthorizedAccessException("The managed operation arguments exceed its manifest.");
        }

        return new AuthorizedManagedOperation(
            request.ProviderId,
            request.OperationId,
            new Dictionary<string, string>(request.Arguments, StringComparer.Ordinal),
            new HashSet<string>(request.RequestedRootIds, StringComparer.Ordinal),
            request.Timeout);
    }

    private static void ValidateManifest(WindowsTaskProviderManifest manifest)
    {
        if (string.IsNullOrWhiteSpace(manifest.ProviderId)
            || !IsIdentifier(manifest.ProviderId)
            || string.IsNullOrWhiteSpace(manifest.Version)
            || manifest.Version.Length > 64
            || string.IsNullOrWhiteSpace(manifest.HandlerAssemblySha256)
            || manifest.HandlerAssemblySha256.Length != 64
            || !manifest.HandlerAssemblySha256.All(char.IsAsciiHexDigit)
            || manifest.Operations is null
            || manifest.Operations.Count is < 1 or > 128)
        {
            throw new ArgumentException("The managed provider manifest is invalid.", nameof(manifest));
        }

        var operationIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var operation in manifest.Operations)
        {
            if (string.IsNullOrWhiteSpace(operation.OperationId)
                || !IsIdentifier(operation.OperationId)
                || operation.MaximumDuration <= TimeSpan.Zero
                || operation.MaximumDuration > TimeSpan.FromHours(2)
                || operation.OperationId.Contains("shell", StringComparison.OrdinalIgnoreCase)
                || operation.OperationId.Contains("powershell", StringComparison.OrdinalIgnoreCase)
                || operation.AcceptedArguments.Count > 64
                || operation.AllowedRootIds.Count > 32
                || operation.AcceptedArguments.Any(argument =>
                    string.IsNullOrWhiteSpace(argument)
                    || argument.Length > 128
                    || ProhibitedArgumentMarkers.Any(marker => argument.Contains(marker, StringComparison.OrdinalIgnoreCase)))
                || operation.AllowedRootIds.Any(rootId => string.IsNullOrWhiteSpace(rootId) || rootId.Length > 64)
                || !operationIds.Add(operation.OperationId))
            {
                throw new ArgumentException("Managed services expose only unique, fixed, non-shell operations.", nameof(manifest));
            }
        }
    }

    private static bool IsIdentifier(string value) =>
        value.Length <= 128
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_');

    private static bool IsSafeRelativePath(string value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.IndexOf('\0') < 0
        && !Path.IsPathRooted(value)
        && !value.StartsWith('\\')
        && !value.StartsWith('/')
        && !(value.Length >= 2 && char.IsAsciiLetter(value[0]) && value[1] == ':')
        && value.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries)
            .All(segment => segment is not "." and not "..");
}
