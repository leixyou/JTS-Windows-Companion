using System.IO;
using System.IO.Pipes;
using System.Text.Json;
using JTS.WindowsCompanion.Elevation;
using JTS.WindowsCompanion.Managed;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Windows.Elevation;

namespace JTS.WindowsCompanion.Windows.Managed;

public sealed class NamedPipeManagedServiceClient : IManagedServiceClient
{
    private readonly string _pipeName;
    private readonly IManagedServiceProcessAttestor _processAttestor;

    public NamedPipeManagedServiceClient(string pipeName)
    {
        ValidatePipeName(pipeName);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The managed service client is available only on Windows.");
        }

        var agentPath = Environment.ProcessPath
            ?? throw new InvalidOperationException("The running agent executable path is unavailable.");
        _pipeName = pipeName;
        _processAttestor = ManagedServiceAttestationFactory.CreateForAgent(agentPath);
    }

    internal NamedPipeManagedServiceClient(
        string pipeName,
        IManagedServiceProcessAttestor processAttestor)
    {
        ValidatePipeName(pipeName);
        _pipeName = pipeName;
        _processAttestor = processAttestor ?? throw new ArgumentNullException(nameof(processAttestor));
    }

    public bool IsConfigured => true;

    public async ValueTask<ManagedOperationExecutionResult> ExecuteAsync(
        ManagedOperationRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The managed service client is available only on Windows.");
        }

        await using var pipe = new NamedPipeClientStream(
            ".",
            _pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);
        try
        {
            await pipe.ConnectAsync(linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new CompanionProtocolException("MANAGED_SERVICE_UNAVAILABLE", "The managed companion service did not accept a local connection.");
        }

        var serverProcessId = NamedPipePeerProcess.GetServerProcessId(pipe);
        _processAttestor.Attest(serverProcessId);

        var messageId = Guid.NewGuid();
        var message = new ManagedServiceMessage(
            ManagedServiceDispatcher.ProtocolVersion,
            messageId,
            ManagedServiceMessageKind.Execute,
            ControlMessageSerializer.ToElement(new
            {
                request.ProviderId,
                request.OperationId,
                request.Arguments,
                requestedRootIds = request.RequestedRootIds.Order(StringComparer.Ordinal).ToArray(),
                request.Timeout,
            }));
        await LocalIpcJsonCodec.WriteAsync(pipe, message, linked.Token).ConfigureAwait(false);
        var response = await LocalIpcJsonCodec.ReadAsync<ManagedServiceMessage>(pipe, linked.Token).ConfigureAwait(false);
        if (response.Version != ManagedServiceDispatcher.ProtocolVersion || response.MessageId != messageId)
        {
            throw new InvalidDataException("The managed service response is invalid.");
        }

        if (response.Kind == ManagedServiceMessageKind.Error)
        {
            var error = response.Payload.Deserialize<ManagedServiceError>(ControlMessageSerializer.Options)
                ?? throw new InvalidDataException("The managed service error response is invalid.");
            throw new CompanionProtocolException(error.Code, error.Message);
        }

        if (response.Kind != ManagedServiceMessageKind.ExecutionResult)
        {
            throw new InvalidDataException("The managed service returned an unexpected response.");
        }

        return response.Payload.Deserialize<ManagedOperationExecutionResult>(ControlMessageSerializer.Options)
            ?? throw new InvalidDataException("The managed service execution result is missing.");
    }

    private static void ValidatePipeName(string pipeName)
    {
        if (string.IsNullOrWhiteSpace(pipeName)
            || pipeName.Length > 128
            || !pipeName.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_'))
        {
            throw new ArgumentException("The managed service pipe name is invalid.", nameof(pipeName));
        }
    }
}
