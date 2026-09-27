using System.ComponentModel;
using System.Security.Cryptography;
using JTS.WindowsCompanion.Agent;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Security;
using JTS.WindowsCompanion.Transport;

namespace JTS.WindowsCompanion.Tests;

public sealed class CompanionReconnectLoopTests
{
    [Fact]
    public async Task TransportFailuresArePacedWithCappedBackoffBeforeAnotherAttempt()
    {
        using var shutdown = new CancellationTokenSource();
        var firstWait = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var waits = new List<TimeSpan>();
        var attempts = 0;
        var running = CompanionReconnectLoop.RunAsync(_ =>
        {
            attempts++;
            throw Unavailable("open", 31);
        }, shutdown.Token, delay: async (interval, token) =>
        {
            waits.Add(interval);
            if (waits.Count == 1) { firstWait.SetResult(); await release.Task.WaitAsync(token); }
            if (waits.Count == 6) shutdown.Cancel();
            token.ThrowIfCancellationRequested();
        });
        await firstWait.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, attempts);
        Assert.False(running.IsCompleted);
        release.SetResult();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running);
        Assert.Equal(new[] { 1, 2, 4, 8, 8, 8 }, waits.Select(value => (int)value.TotalSeconds));
        Assert.Equal(6, attempts);
    }

    [Fact]
    public async Task CancellationDuringBackoffOrBeforeStartNeverRespawnsASession()
    {
        using var shutdown = new CancellationTokenSource();
        var waiting = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var attempts = 0;
        var running = CompanionReconnectLoop.RunAsync(_ =>
        {
            attempts++;
            throw Unavailable("read", 109);
        }, shutdown.Token, delay: async (_, token) => { waiting.SetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, token); });
        await waiting.Task.WaitAsync(TimeSpan.FromSeconds(5));
        shutdown.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running);
        Assert.Equal(1, attempts);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CompanionReconnectLoop.RunAsync(_ =>
        {
            attempts++;
            return Task.CompletedTask;
        }, shutdown.Token));
        Assert.Equal(1, attempts);
        using var nativeRace = new CancellationTokenSource();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CompanionReconnectLoop.RunAsync(_ =>
        {
            nativeRace.Cancel();
            throw Unavailable("read", 995);
        }, nativeRace.Token, delay: (_, _) => throw new InvalidOperationException("Shutdown must not retry.")));
    }

    [Fact]
    public async Task ProtocolAuthenticationCryptoAndUnclassifiedNativeFailuresRemainFatal()
    {
        foreach (var failure in new Exception[]
        {
            new CompanionProtocolException("FRAME_AUTH_INVALID", "rejected"),
            new CryptographicException("invalid identity"), new Win32Exception(5),
            new IOException("unexpected storage failure"), new InvalidOperationException("invalid configuration"),
        })
        {
            var attempts = 0;
            var thrown = await Assert.ThrowsAnyAsync<Exception>(() => CompanionReconnectLoop.RunAsync(_ =>
            {
                attempts++;
                throw failure;
            }, default, delay: (_, _) => throw new InvalidOperationException("Fatal failures must not back off.")));
            Assert.Same(failure, thrown);
            Assert.Equal(1, attempts);
        }
    }

    [Fact]
    public async Task PairingPromptHonorsPreCancelledTokenWithoutOpeningADialog()
    {
        using var shutdown = new CancellationTokenSource();
        shutdown.Cancel();
        var prompt = new JTS.WindowsCompanion.Windows.Security.WindowsCompanionPairingConsentPrompt();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => prompt.ConfirmAsync(
            new CompanionPeerIdentity(Guid.NewGuid(), new string('A', 64), "unused"), shutdown.Token).AsTask());
    }

    [Fact]
    public async Task CleanSessionEndAlsoWaitsAndHonorsShutdown()
    {
        using var shutdown = new CancellationTokenSource();
        var attempts = 0;
        var delays = 0;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CompanionReconnectLoop.RunAsync(_ =>
        {
            attempts++;
            return Task.CompletedTask;
        }, shutdown.Token, delay: (_, token) =>
        {
            delays++;
            shutdown.Cancel();
            token.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }));
        Assert.Equal(1, attempts);
        Assert.Equal(1, delays);
    }

    [Fact]
    public async Task FreshAgentGenerationResetsAuthorizationReplayAndOutboundSequence()
    {
        using var shutdown = new CancellationTokenSource();
        var channels = new List<GenerationChannel>();
        var gates = new List<ResettingGate>();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CompanionReconnectLoop.RunAsync(async token =>
        {
            Assert.All(channels, previous => Assert.True(previous.Disposed));
            Assert.All(gates, previous => Assert.False(previous.IsAuthorized));
            await using var channel = new GenerationChannel();
            channels.Add(channel);
            var gate = new ResettingGate();
            gates.Add(gate);
            var agent = new CompanionAgent(channel, new CompanionRequestRouter(gate));
            await agent.RunAsync(_ =>
            {
                Assert.False(gate.IsAuthorized);
                gate.IsAuthorized = true; // Represents a fresh authorized session.
                return ValueTask.CompletedTask;
            }, token);
        }, shutdown.Token, delay: (_, token) =>
        {
            if (channels.Count == 2) shutdown.Cancel();
            token.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }));
        Assert.Equal(2, channels.Count);
        Assert.All(channels, channel =>
        {
            Assert.True(channel.Disposed);
            var pong = Assert.Single(channel.Sent);
            Assert.Equal(CompanionFrameType.Pong, pong.Type);
            Assert.Equal(1UL, pong.Sequence);
        });
        Assert.All(gates, gate => { Assert.False(gate.IsAuthorized); Assert.Equal(2, gate.Resets); });
    }

    [Fact]
    public async Task SendFailureDrainsTheCancelledReceiveBeforeDisposingOrReopening()
    {
        using var shutdown = new CancellationTokenSource();
        var channel = new DrainingChannel();
        var attempts = 0;
        var running = CompanionReconnectLoop.RunAsync(async token =>
        {
            attempts++;
            await using var lifetime = channel;
            var router = new CompanionRequestRouter(new ResettingGate());
            var agent = new CompanionAgent(channel, router);
            await agent.RunAsync(token);
        }, shutdown.Token, delay: (_, token) =>
        {
            shutdown.Cancel();
            token.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        });
        await channel.ReceiveCancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.False(channel.Disposed);
        Assert.False(running.IsCompleted);
        channel.ReleaseReceive.SetResult();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running);
        Assert.True(channel.Disposed);
        Assert.Equal(1, attempts);
    }

    private static CompanionChannelUnavailableException Unavailable(string operation, int code) => new(operation, code, new Win32Exception(code));

    private sealed class ResettingGate : ICompanionAuthorizationGate
    {
        public bool IsAuthorized { get; set; } = true;
        public int Resets { get; private set; }
        public CompanionAuthorizationDecision Evaluate(string method) => new(true, true, null);
        public void ResetSession() { Resets++; IsAuthorized = false; }
    }

    private sealed class GenerationChannel : ICompanionChannel
    {
        private int _readCount;
        public List<CompanionFrame> Sent { get; } = [];
        public bool Disposed { get; private set; }
        public bool IsConnected { get; private set; }
        public ValueTask ConnectAsync(CancellationToken cancellationToken) { IsConnected = true; return ValueTask.CompletedTask; }
        public ValueTask<CompanionFrame> ReceiveAsync(CancellationToken cancellationToken) => ++_readCount == 1
            ? ValueTask.FromResult(new CompanionFrame(CompanionProtocol.CurrentVersion, CompanionFrameType.Ping, CompanionFrameFlags.Final, 1, ReadOnlyMemory<byte>.Empty))
            : ValueTask.FromException<CompanionFrame>(Unavailable("read", 109));
        public ValueTask SendAsync(CompanionFrame frame, CancellationToken cancellationToken) { Sent.Add(frame); return ValueTask.CompletedTask; }
        public ValueTask DisposeAsync() { Disposed = true; IsConnected = false; return ValueTask.CompletedTask; }
    }

    private sealed class DrainingChannel : ICompanionChannel
    {
        private int _readCount;
        public bool IsConnected => !Disposed;
        public bool Disposed { get; private set; }
        public TaskCompletionSource ReceiveCancelled { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseReceive { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public ValueTask ConnectAsync(CancellationToken cancellationToken) => ValueTask.CompletedTask;
        public async ValueTask<CompanionFrame> ReceiveAsync(CancellationToken cancellationToken)
        {
            if (++_readCount == 1)
            {
                var request = new CompanionRequest(CompanionProtocol.CurrentVersion, Guid.NewGuid(), "companion.state", null, null, null, System.Text.Json.JsonSerializer.SerializeToElement(new { }));
                return new CompanionFrame(CompanionProtocol.CurrentVersion, CompanionFrameType.ControlJson, CompanionFrameFlags.Final, 1, ControlMessageSerializer.Serialize(request));
            }
            try { await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); }
            catch (OperationCanceledException)
            {
                ReceiveCancelled.SetResult();
                await ReleaseReceive.Task;
                throw;
            }
            throw new InvalidOperationException();
        }
        public async ValueTask SendAsync(CompanionFrame frame, CancellationToken cancellationToken)
        {
            await Task.Yield();
            throw Unavailable("write", 232);
        }
        public ValueTask DisposeAsync() { Disposed = true; return ValueTask.CompletedTask; }
    }
}
