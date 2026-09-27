using System.Net;
using System.Net.Sockets;
using JTS.WindowsCompanion.Pairing;
using JTS.WindowsCompanion.Relay;

namespace JTS.WindowsCompanion.Control;

/// <summary>One authorized RDP stream to the installed machine's fixed loopback listener. No arbitrary TCP forwarding.</summary>
public sealed class RelayRdpLane(DurableRelayPairingStore pairings) : ICompanionRelayLaneHandler
{
    public async Task ServeAsync(Stream stream, string ownerDeviceId, CancellationToken cancellationToken)
    {
        var request = await LaneRequest.ReadAsync(stream, cancellationToken).ConfigureAwait(false)
            ?? throw new ControlProtocolException("LANE_OPEN_REQUIRED");
        using var target = new TcpClient(AddressFamily.InterNetwork);
        try
        {
            request.RequireOpen("rdp.open");
            await LaneRequest.AuthorizeAsync(pairings, ownerDeviceId, RelayLane.Rdp, request.GrantId, cancellationToken).ConfigureAwait(false);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(TimeSpan.FromSeconds(10));
            await target.ConnectAsync(IPAddress.Loopback, 3389, deadline.Token).ConfigureAwait(false);
            await LaneRequest.AuthorizeAsync(pairings, ownerDeviceId, RelayLane.Rdp, request.GrantId, cancellationToken).ConfigureAwait(false);
            await request.ReplyAsync(stream, new { ready = true }, null, deadline.Token).ConfigureAwait(false);
        }
        catch (Exception error) when (error is ControlProtocolException or SocketException)
        {
            await request.ReplyAsync(stream, null, error is ControlProtocolException protocol ? protocol.Code : "RDP_LISTENER_UNAVAILABLE", cancellationToken).ConfigureAwait(false);
            return;
        }
        // The shared service cancels this lease when the pairing changes/expires, including during idle desktop sessions.
        await RelayRdpBridge.RunAsync(stream, target, token => MonitorAsync(ownerDeviceId, request.GrantId, token), cancellationToken).ConfigureAwait(false);
    }
    private async Task MonitorAsync(string owner, Guid grant, CancellationToken token)
    {
        while (true)
        {
            await Task.Delay(TimeSpan.FromSeconds(2), token).ConfigureAwait(false);
            await LaneRequest.AuthorizeAsync(pairings, owner, RelayLane.Rdp, grant, token).ConfigureAwait(false);
        }
    }
}
