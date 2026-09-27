using System.Text.Json;
using JTS.WindowsCompanion.Elevation;
using JTS.WindowsCompanion.Protocol;

namespace JTS.WindowsCompanion.Managed;

public enum ManagedServiceMessageKind
{
    Execute,
    ExecutionResult,
    Error,
}

public sealed record ManagedServiceMessage(
    int Version,
    Guid MessageId,
    ManagedServiceMessageKind Kind,
    JsonElement Payload);

public sealed record ManagedServiceError(string Code, string Message);

public interface IManagedServiceClient
{
    bool IsConfigured { get; }

    ValueTask<ManagedOperationExecutionResult> ExecuteAsync(
        ManagedOperationRequest request,
        CancellationToken cancellationToken);
}

public sealed class UnavailableManagedServiceClient : IManagedServiceClient
{
    public static UnavailableManagedServiceClient Instance { get; } = new();

    private UnavailableManagedServiceClient()
    {
    }

    public bool IsConfigured => false;

    public ValueTask<ManagedOperationExecutionResult> ExecuteAsync(
        ManagedOperationRequest request,
        CancellationToken cancellationToken) =>
        ValueTask.FromException<ManagedOperationExecutionResult>(new CompanionProtocolException(
            "MANAGED_SERVICE_REQUIRED",
            "The optional release-verified managed companion service is not configured."));
}

public sealed class ManagedServiceDispatcher
{
    public const int ProtocolVersion = 1;
    private readonly InstalledManagedProviderStore _providers;
    private readonly ManagedServicePolicy _policy;
    private readonly IManagedOperationExecutor _executor;

    public ManagedServiceDispatcher(
        InstalledManagedProviderStore providers,
        IManagedOperationExecutor executor)
    {
        _providers = providers ?? throw new ArgumentNullException(nameof(providers));
        _policy = new ManagedServicePolicy(providers.Providers.Select(provider => provider.Manifest));
        _executor = executor ?? throw new ArgumentNullException(nameof(executor));
    }

    public async ValueTask HandleOneAsync(Stream stream, CancellationToken cancellationToken)
    {
        var request = await LocalIpcJsonCodec.ReadAsync<ManagedServiceMessage>(stream, cancellationToken).ConfigureAwait(false);
        ManagedServiceMessage response;
        try
        {
            if (request.Version != ProtocolVersion
                || request.MessageId == Guid.Empty
                || request.Kind != ManagedServiceMessageKind.Execute)
            {
                throw new ArgumentException("The managed service request is invalid.", nameof(request));
            }

            var document = request.Payload.Deserialize<ManagedOperationRequestDocument>(ControlMessageSerializer.Options)
                ?? throw new ArgumentException("The managed operation payload is missing.", nameof(request));
            var operationRequest = new ManagedOperationRequest(
                document.ProviderId,
                document.OperationId,
                document.Arguments,
                new HashSet<string>(document.RequestedRootIds, StringComparer.Ordinal),
                document.Timeout);
            var operation = _policy.Authorize(operationRequest);
            var provider = _providers.Get(operation.ProviderId);
            var result = await _executor.ExecuteAsync(provider, operation, cancellationToken).ConfigureAwait(false);
            response = Message(request.MessageId, ManagedServiceMessageKind.ExecutionResult, result);
        }
        catch (UnauthorizedAccessException)
        {
            response = Message(
                request.MessageId,
                ManagedServiceMessageKind.Error,
                new ManagedServiceError("NOT_AUTHORIZED", "The managed operation is not installed or allowed."));
        }
        catch (ArgumentException)
        {
            response = Message(
                request.MessageId,
                ManagedServiceMessageKind.Error,
                new ManagedServiceError("REQUEST_INVALID", "The managed operation request is invalid."));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            response = Message(
                request.MessageId,
                ManagedServiceMessageKind.Error,
                new ManagedServiceError("EXECUTION_FAILED", "The installed managed operation failed."));
        }

        await LocalIpcJsonCodec.WriteAsync(stream, response, cancellationToken).ConfigureAwait(false);
    }

    private static ManagedServiceMessage Message<T>(Guid id, ManagedServiceMessageKind kind, T payload) => new(
        ProtocolVersion,
        id,
        kind,
        ControlMessageSerializer.ToElement(payload));

    private sealed record ManagedOperationRequestDocument(
        string ProviderId,
        string OperationId,
        IReadOnlyDictionary<string, string> Arguments,
        IReadOnlyList<string> RequestedRootIds,
        TimeSpan Timeout);
}
