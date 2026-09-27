using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Xunit;

namespace JTS.WindowsCompanion.Control.Tests;

public sealed class RelayRdpBridgeTests
{
    [Fact]
    public async Task ControllerHalfCloseDrainsTheTargetsFinalResponse()
    {
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var remoteListener = new TcpListener(IPAddress.Loopback, 0); remoteListener.Start();
        using var controller = new TcpClient(); await controller.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)remoteListener.LocalEndpoint).Port, stop.Token);
        using var acceptedController = await remoteListener.AcceptTcpClientAsync(stop.Token);
        var controllerStream = controller.GetStream();
        using var targetListener = new TcpListener(IPAddress.Loopback, 0); targetListener.Start();
        using var target = new TcpClient(); await target.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)targetListener.LocalEndpoint).Port, stop.Token);
        using var acceptedTarget = await targetListener.AcceptTcpClientAsync(stop.Token);
        var bridge = RelayRdpBridge.RunAsync(acceptedController.GetStream(), target, token => Task.Delay(Timeout.Infinite, token), stop.Token);
        var payload = RandomNumberGenerator.GetBytes(65536);
        var echo = Task.Run(async () =>
        {
            using var received = new MemoryStream(); await acceptedTarget.GetStream().CopyToAsync(received, stop.Token);
            Assert.Equal(payload, received.ToArray());
            await acceptedTarget.GetStream().WriteAsync(received.ToArray(), stop.Token); acceptedTarget.Client.Shutdown(SocketShutdown.Send);
        });
        await controllerStream.WriteAsync(payload, stop.Token); controller.Client.Shutdown(SocketShutdown.Send);
        var answer = new byte[payload.Length]; await controllerStream.ReadExactlyAsync(answer, stop.Token);
        Assert.Equal(payload, answer); await echo; await bridge;
    }
}
