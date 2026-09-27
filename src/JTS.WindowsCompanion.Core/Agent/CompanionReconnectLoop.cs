using JTS.WindowsCompanion.Transport;

namespace JTS.WindowsCompanion.Agent;

/// <summary>Serial in-process channel generations, with cancellation-aware bounded backoff.</summary>
public static class CompanionReconnectLoop
{
    public static async Task RunAsync(
        Func<CancellationToken, Task> runSession,
        CancellationToken cancellationToken,
        Action<CompanionChannelUnavailableException?, TimeSpan>? onRetry = null,
        Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        ArgumentNullException.ThrowIfNull(runSession);
        var retrySeconds = 1;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CompanionChannelUnavailableException? transportFailure = null;
            try
            {
                // The factory must drain and dispose its generation before returning.
                await runSession(cancellationToken).ConfigureAwait(false);
            }
            catch (CompanionChannelUnavailableException exception)
            {
                cancellationToken.ThrowIfCancellationRequested();
                transportFailure = exception;
            }
            cancellationToken.ThrowIfCancellationRequested();
            var interval = TimeSpan.FromSeconds(retrySeconds);
            onRetry?.Invoke(transportFailure, interval);
            if (delay is null) await Task.Delay(interval, cancellationToken).ConfigureAwait(false);
            else await delay(interval, cancellationToken).ConfigureAwait(false);
            retrySeconds = Math.Min(8, retrySeconds * 2);
        }
    }
}
