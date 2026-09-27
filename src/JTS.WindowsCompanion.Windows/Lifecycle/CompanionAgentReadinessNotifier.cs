using System.IO;
using System.IO.Pipes;

namespace JTS.WindowsCompanion.Lifecycle;

public static class CompanionAgentReadinessNotifier
{
    private static readonly TimeSpan ConnectionTimeout = TimeSpan.FromSeconds(2);

    public static async ValueTask TryNotifyAsync(
        string pipeName,
        CancellationToken cancellationToken)
    {
        CompanionAgentReadinessContract.ValidatePipeName(pipeName);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(ConnectionTimeout);
            await using var pipe = new NamedPipeClientStream(
                ".",
                pipeName,
                PipeDirection.Out,
                PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
            await pipe.WriteAsync(
                new[] { CompanionAgentReadinessContract.ProtocolVersion },
                timeout.Token).ConfigureAwait(false);
            await pipe.FlushAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is IOException or
            UnauthorizedAccessException or
            TimeoutException or
            OperationCanceledException)
        {
            // Setup may have exited or been terminated. Readiness notification must not stop a healthy Agent.
        }
    }
}
