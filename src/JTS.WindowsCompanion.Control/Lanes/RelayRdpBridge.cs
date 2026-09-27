using System.Net.Sockets;

namespace JTS.WindowsCompanion.Control;

internal static class RelayRdpBridge
{
    internal static async Task RunAsync(Stream controller, TcpClient target, Func<CancellationToken, Task> monitor, CancellationToken token)
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(token);
        await using var network = target.GetStream();
        var outbound = controller.CopyToAsync(network, 65536, stop.Token);
        var inbound = network.CopyToAsync(controller, 65536, stop.Token);
        var authority = monitor(stop.Token);
        try
        {
            var first = await Task.WhenAny(outbound, inbound, authority).ConfigureAwait(false);
            await first.ConfigureAwait(false);
            if (first == outbound)
            {
                // Controller EOF is a send half-close: the local RDP endpoint may still have a final response.
                target.Client.Shutdown(SocketShutdown.Send);
                var drained = await Task.WhenAny(inbound, authority).WaitAsync(TimeSpan.FromSeconds(15), token).ConfigureAwait(false);
                await drained.ConfigureAwait(false);
            }
            if (inbound.IsCompletedSuccessfully) await controller.FlushAsync(token).ConfigureAwait(false);
        }
        finally
        {
            stop.Cancel(); target.Close();
            try { await Task.WhenAll(outbound, inbound, authority).ConfigureAwait(false); }
            catch (Exception error) when (error is IOException or OperationCanceledException or ObjectDisposedException) { }
        }
    }
}
