using System.IO.Pipes;
using System.Runtime.Versioning;
using JTS.WindowsCompanion.Lifecycle;

namespace JTS.WindowsCompanion.Tests;

public sealed class CompanionAgentReadinessTests
{
    [Fact]
    public void Contract_AcceptsOnlyGeneratedPipeNames()
    {
        var pipeName = CompanionAgentReadinessContract.CreatePipeName();

        Assert.True(CompanionAgentReadinessContract.IsValidPipeName(pipeName));
        Assert.False(CompanionAgentReadinessContract.IsValidPipeName(null));
        Assert.False(CompanionAgentReadinessContract.IsValidPipeName("JTS.Terminal.Agent.Ready.not-a-guid"));
        Assert.False(CompanionAgentReadinessContract.IsValidPipeName("untrusted-" + Guid.NewGuid().ToString("N")));
    }

    [WindowsIntegrationFact]
    [SupportedOSPlatform("windows10.0")]
    public async Task Server_AcceptsTheExpectedWindowsProcessAndProtocolByte()
    {
        using var server = new CompanionAgentReadinessServer();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var wait = server.WaitForReadyAsync(
            Environment.ProcessId,
            TimeSpan.FromSeconds(5),
            timeout.Token);

        await CompanionAgentReadinessNotifier.TryNotifyAsync(server.PipeName, timeout.Token);
        await wait;
    }

    [WindowsIntegrationFact]
    [SupportedOSPlatform("windows10.0")]
    public async Task Server_RejectsAConnectedProcessWithTheWrongExpectedPid()
    {
        using var server = new CompanionAgentReadinessServer();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var wait = server.WaitForReadyAsync(
            Environment.ProcessId + 1,
            TimeSpan.FromSeconds(5),
            timeout.Token);

        await CompanionAgentReadinessNotifier.TryNotifyAsync(server.PipeName, timeout.Token);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => wait);
    }

    [WindowsIntegrationFact]
    [SupportedOSPlatform("windows10.0")]
    public async Task Server_RejectsAnInvalidProtocolByte()
    {
        using var server = new CompanionAgentReadinessServer();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var wait = server.WaitForReadyAsync(
            Environment.ProcessId,
            TimeSpan.FromSeconds(5),
            timeout.Token);
        await using var client = new NamedPipeClientStream(
            ".",
            server.PipeName,
            PipeDirection.Out,
            PipeOptions.Asynchronous);
        await client.ConnectAsync(timeout.Token);
        await client.WriteAsync(new byte[] { 0xFF }, timeout.Token);
        await client.FlushAsync(timeout.Token);

        await Assert.ThrowsAsync<InvalidDataException>(() => wait);
    }
}
