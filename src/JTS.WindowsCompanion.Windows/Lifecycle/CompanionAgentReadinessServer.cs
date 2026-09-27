using System.IO;
using System.IO.Pipes;
using JTS.WindowsCompanion.Windows.Elevation;

namespace JTS.WindowsCompanion.Lifecycle;

public sealed class CompanionAgentReadinessServer : IDisposable
{
    private readonly NamedPipeServerStream _pipe;
    private bool _waitStarted;

    public CompanionAgentReadinessServer()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Agent startup readiness is available only on Windows.");
        }

        PipeName = CompanionAgentReadinessContract.CreatePipeName();
        _pipe = new NamedPipeServerStream(
            PipeName,
            PipeDirection.In,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
    }

    public string PipeName { get; }

    public async Task WaitForReadyAsync(
        int expectedProcessId,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (expectedProcessId <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(expectedProcessId));
        }
        if (_waitStarted)
        {
            throw new InvalidOperationException("Agent startup readiness can be awaited only once.");
        }
        _waitStarted = true;

        using var timeoutCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCancellation.CancelAfter(timeout);
        try
        {
            await _pipe.WaitForConnectionAsync(timeoutCancellation.Token).ConfigureAwait(false);
            var actualProcessId = NamedPipePeerProcess.GetClientProcessId(_pipe);
            if (actualProcessId != expectedProcessId)
            {
                throw new UnauthorizedAccessException(
                    "Agent startup readiness came from an unexpected process.");
            }

            var ready = new byte[1];
            var bytesRead = await _pipe.ReadAsync(ready, timeoutCancellation.Token).ConfigureAwait(false);
            if (bytesRead != 1 || ready[0] != CompanionAgentReadinessContract.ProtocolVersion)
            {
                throw new InvalidDataException("The Agent startup readiness response is invalid.");
            }
        }
        catch (OperationCanceledException exception) when (
            timeoutCancellation.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException(
                "The installed Companion Agent did not become ready in time.",
                exception);
        }
    }

    public void Dispose() => _pipe.Dispose();
}
