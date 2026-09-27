using System.Security.Cryptography;
using System.Threading.Channels;
using JTS.WindowsCompanion.Agent;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Security;
using JTS.WindowsCompanion.Transport;

namespace JTS.WindowsCompanion.Tests;

public sealed class CompanionAgentCancellationTests
{
    [Fact]
    public async Task AuthenticatedExactCancellationTargetsOneRequestAndKeepsAgentAlive()
    {
        await using var fixture = new AuthenticatedAgentFixture();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Router.Register("test.slow", async (_, cancellationToken) =>
        {
            started.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return new { completed = true };
        });
        fixture.Router.Register("test.state", (_, _) =>
            ValueTask.FromResult<object?>(new { alive = true }));
        fixture.Start();
        var slow = fixture.Request("test.slow", new { });
        await fixture.InjectAsync(slow, sequence: 1);
        await started.Task.WaitAsync(fixture.TimeoutToken);

        var cancel = fixture.Request(
            "companion.cancel",
            new { requestId = slow.RequestId });
        await fixture.InjectAsync(cancel, sequence: 2);
        var responses = await fixture.ReadResponsesAsync(2);

        Assert.Equal("REQUEST_CANCELLED", responses[slow.RequestId].Error?.Code);
        Assert.True(responses[cancel.RequestId].Success);
        Assert.True(responses[cancel.RequestId].Result?.GetProperty("cancelled").GetBoolean());

        var state = fixture.Request("test.state", new { });
        await fixture.InjectAsync(state, sequence: 3);
        var stateResponse = await fixture.ReadResponseAsync();
        Assert.True(stateResponse.Success);
        Assert.True(stateResponse.Result?.GetProperty("alive").GetBoolean());
    }

    [Fact]
    public async Task AuthenticatedCancelPendingDrainsOnlyTheLiveOwnerAndPreservesPairing()
    {
        await using var fixture = new AuthenticatedAgentFixture();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var startedCount = 0;
        fixture.Router.Register("test.slow", async (_, cancellationToken) =>
        {
            if (Interlocked.Increment(ref startedCount) == 2)
            {
                started.TrySetResult();
            }

            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return new { completed = true };
        });
        fixture.Router.Register("test.state", (_, _) =>
            ValueTask.FromResult<object?>(new { paired = true }));
        fixture.Start();
        var first = fixture.Request("test.slow", new { });
        var second = fixture.Request("test.slow", new { });
        await fixture.InjectAsync(first, sequence: 1);
        await fixture.InjectAsync(second, sequence: 2);
        await started.Task.WaitAsync(fixture.TimeoutToken);

        var cancelPending = fixture.Request("companion.cancelPending", new { });
        await fixture.InjectAsync(cancelPending, sequence: 3);
        var responses = await fixture.ReadResponsesAsync(3);

        Assert.Equal("REQUEST_CANCELLED", responses[first.RequestId].Error?.Code);
        Assert.Equal("REQUEST_CANCELLED", responses[second.RequestId].Error?.Code);
        Assert.True(responses[cancelPending.RequestId].Success);
        Assert.Equal(
            2,
            responses[cancelPending.RequestId].Result?.GetProperty("cancelled").GetInt32());

        var state = fixture.Request("test.state", new { });
        await fixture.InjectAsync(state, sequence: 4);
        var stateResponse = await fixture.ReadResponseAsync();
        Assert.True(stateResponse.Success);
        Assert.True(stateResponse.Result?.GetProperty("paired").GetBoolean());
    }

    [Fact]
    public async Task OperationDeadlineReturnsSanitizedFailureWithoutStoppingAgent()
    {
        var now = new DateTimeOffset(2026, 7, 15, 10, 0, 0, TimeSpan.Zero);
        var timeProvider = new ManualTimeProvider(now);
        await using var fixture = new AuthenticatedAgentFixture(timeProvider);
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Router.Register("test.slow", async (_, cancellationToken) =>
        {
            started.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return new { completed = true };
        });
        fixture.Router.Register("test.state", (_, _) =>
            ValueTask.FromResult<object?>(new { alive = true }));
        fixture.Start();
        var request = fixture.Request(
            "test.slow",
            new { },
            deadlineUnixMilliseconds: now.AddSeconds(1).ToUnixTimeMilliseconds());
        await fixture.InjectAsync(request, sequence: 1);
        await started.Task.WaitAsync(fixture.TimeoutToken);

        timeProvider.Advance(TimeSpan.FromSeconds(1));
        var deadlineResponse = await fixture.ReadResponseAsync();
        Assert.Equal(request.RequestId, deadlineResponse.RequestId);
        Assert.Equal("DEADLINE_EXCEEDED", deadlineResponse.Error?.Code);

        var state = fixture.Request("test.state", new { });
        await fixture.InjectAsync(state, sequence: 2);
        Assert.True((await fixture.ReadResponseAsync()).Success);
    }

    [Fact]
    public async Task UnpairCancelsDrainsAndFencesNewOwnedOperationsBeforeRevocation()
    {
        await using var fixture = new AuthenticatedAgentFixture();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cancellationObserved = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseCancellation = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Router.Register("test.slow", async (_, cancellationToken) =>
        {
            started.TrySetResult();
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                return new { completed = true };
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                cancellationObserved.TrySetResult();
                await releaseCancellation.Task;
                throw;
            }
        });
        fixture.Router.Register("companion.unpair", (_, _) =>
            ValueTask.FromResult<object?>(new { revoked = true }));
        fixture.Router.Register("test.state", (_, _) =>
            ValueTask.FromResult<object?>(new { shouldNotRun = true }));
        fixture.Start();
        var slow = fixture.Request("test.slow", new { });
        await fixture.InjectAsync(slow, sequence: 1);
        await started.Task.WaitAsync(fixture.TimeoutToken);

        var unpair = fixture.Request("companion.unpair", new { });
        await fixture.InjectAsync(unpair, sequence: 2);
        await cancellationObserved.Task.WaitAsync(fixture.TimeoutToken);
        var fenced = fixture.Request("test.state", new { });
        await fixture.InjectAsync(fenced, sequence: 3);
        var fencedResponse = await fixture.ReadResponseAsync();
        Assert.Equal(fenced.RequestId, fencedResponse.RequestId);
        Assert.Equal("REQUEST_CANCELLED", fencedResponse.Error?.Code);

        releaseCancellation.TrySetResult();
        var responses = await fixture.ReadResponsesAsync(2);
        Assert.Equal("REQUEST_CANCELLED", responses[slow.RequestId].Error?.Code);
        Assert.True(responses[unpair.RequestId].Success);
        Assert.True(responses[unpair.RequestId].Result?.GetProperty("revoked").GetBoolean());
    }

    private sealed class AuthenticatedAgentFixture : IAsyncDisposable
    {
        private readonly CancellationTokenSource _timeout = new(TimeSpan.FromSeconds(10));
        private readonly CancellationTokenSource _runtime = new();
        private readonly MemoryChannel _channel = new();
        private readonly TestIdentity _windowsIdentity = new();
        private readonly TestIdentity _clientIdentity = new();
        private readonly byte[] _sessionBinding = SHA256.HashData("agent-cancellation-session"u8);
        private readonly TimeProvider _timeProvider;
        private Task? _execution;

        public AuthenticatedAgentFixture(TimeProvider? timeProvider = null)
        {
            _timeProvider = timeProvider ?? TimeProvider.System;
            var context = new CompanionFrameAuthenticationContext(
                _sessionBinding,
                Convert.FromBase64String(_clientIdentity.Metadata.PublicKeyBase64));
            var authorization = new FixedAuthorizedSession(context);
            Router = new CompanionRequestRouter(authorization);
            Agent = new CompanionAgent(
                _channel,
                Router,
                frameAuthenticator: new CompanionFrameAuthenticator(_windowsIdentity, authorization),
                timeProvider: _timeProvider);
        }

        public CompanionAgent Agent { get; }

        public CompanionRequestRouter Router { get; }

        public CancellationToken TimeoutToken => _timeout.Token;

        public void Start() => _execution = Agent.RunAsync(_runtime.Token);

        public CompanionRequest Request(
            string method,
            object parameters,
            long? deadlineUnixMilliseconds = null) => new(
                CompanionProtocol.CurrentVersion,
                Guid.NewGuid(),
                method,
                deadlineUnixMilliseconds
                    ?? _timeProvider.GetUtcNow().AddMinutes(1).ToUnixTimeMilliseconds(),
                null,
                null,
                ControlMessageSerializer.ToElement(parameters));

        public ValueTask InjectAsync(CompanionRequest request, ulong sequence)
        {
            var frame = new CompanionFrame(
                CompanionProtocol.CurrentVersion,
                CompanionFrameType.ControlJson,
                CompanionFrameFlags.Final,
                sequence,
                ControlMessageSerializer.Serialize(request));
            return _channel.InjectAsync(_clientIdentity.ProtectInbound(frame, _sessionBinding));
        }

        public async Task<Dictionary<Guid, CompanionResponse>> ReadResponsesAsync(int count)
        {
            var responses = new Dictionary<Guid, CompanionResponse>();
            while (responses.Count < count)
            {
                var response = await ReadResponseAsync();
                responses.Add(response.RequestId, response);
            }

            return responses;
        }

        public async Task<CompanionResponse> ReadResponseAsync()
        {
            var frame = await _channel.ReadSentAsync(_timeout.Token);
            _windowsIdentity.VerifyOutbound(frame, _sessionBinding);
            return ControlMessageSerializer.Deserialize<CompanionResponse>(
                frame.Payload.Span[CompanionProtocol.FrameAuthenticationEnvelopeBytes..]);
        }

        public async ValueTask DisposeAsync()
        {
            _runtime.Cancel();
            if (_execution is not null)
            {
                await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                    await _execution);
            }

            _timeout.Dispose();
            _runtime.Dispose();
            _windowsIdentity.Dispose();
            _clientIdentity.Dispose();
            await _channel.DisposeAsync();
        }
    }

    private sealed class FixedAuthorizedSession :
        ICompanionAuthorizationGate,
        ICompanionFrameAuthenticationContextSource
    {
        private readonly CompanionFrameAuthenticationContext _context;

        public FixedAuthorizedSession(CompanionFrameAuthenticationContext context)
        {
            _context = context;
        }

        public bool IsAuthorized => true;

        public CompanionAuthorizationDecision Evaluate(string method) =>
            new(true, false, "fixed-authorized-peer");

        public void ResetSession()
        {
        }

        public bool TryGetFrameAuthenticationContext(
            out CompanionFrameAuthenticationContext? context)
        {
            context = _context;
            return true;
        }
    }

    private sealed class TestIdentity : ICompanionIdentity, IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public TestIdentity()
        {
            var publicKey = _key.ExportSubjectPublicKeyInfo();
            Metadata = new CompanionIdentityMetadata(
                Guid.NewGuid(),
                Convert.ToHexString(SHA256.HashData(publicKey)),
                Convert.ToBase64String(publicKey));
        }

        public CompanionIdentityMetadata Metadata { get; }

        public ValueTask<CompanionIdentityMetadata> GetMetadataAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(Metadata);

        public ValueTask<byte[]> SignAsync(
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken) => ValueTask.FromResult(_key.SignData(
                payload.Span,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        public CompanionFrame ProtectInbound(CompanionFrame frame, byte[] binding)
        {
            var flags = frame.Flags | CompanionFrameFlags.Authenticated;
            var canonical = CompanionFrameAuthenticator.BuildCanonicalPayload(
                frame.Version,
                CompanionFrameDirection.MacToWindows,
                frame.Type,
                flags,
                frame.Sequence,
                frame.Payload.Span,
                binding);
            var signature = _key.SignData(
                canonical,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            var payload = new byte[CompanionProtocol.FrameAuthenticationEnvelopeBytes + frame.Payload.Length];
            "JTSA"u8.CopyTo(payload);
            signature.CopyTo(payload.AsSpan(4));
            frame.Payload.Span.CopyTo(payload.AsSpan(CompanionProtocol.FrameAuthenticationEnvelopeBytes));
            return frame with { Flags = flags, Payload = payload };
        }

        public void VerifyOutbound(CompanionFrame frame, byte[] binding)
        {
            Assert.True(frame.Flags.HasFlag(CompanionFrameFlags.Authenticated));
            Assert.True(frame.Payload.Span[..4].SequenceEqual("JTSA"u8));
            var applicationPayload = frame.Payload[CompanionProtocol.FrameAuthenticationEnvelopeBytes..];
            var canonical = CompanionFrameAuthenticator.BuildCanonicalPayload(
                frame.Version,
                CompanionFrameDirection.WindowsToMac,
                frame.Type,
                frame.Flags,
                frame.Sequence,
                applicationPayload.Span,
                binding);
            Assert.True(_key.VerifyData(
                canonical,
                frame.Payload.Span.Slice(4, 64),
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        }

        public void Dispose() => _key.Dispose();
    }

    private sealed class MemoryChannel : ICompanionChannel
    {
        private readonly Channel<CompanionFrame> _inbound = Channel.CreateUnbounded<CompanionFrame>();
        private readonly Channel<CompanionFrame> _outbound = Channel.CreateUnbounded<CompanionFrame>();

        public bool IsConnected { get; private set; }

        public ValueTask ConnectAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            IsConnected = true;
            return ValueTask.CompletedTask;
        }

        public ValueTask<CompanionFrame> ReceiveAsync(CancellationToken cancellationToken) =>
            _inbound.Reader.ReadAsync(cancellationToken);

        public ValueTask SendAsync(CompanionFrame frame, CancellationToken cancellationToken) =>
            _outbound.Writer.WriteAsync(frame, cancellationToken);

        public ValueTask InjectAsync(CompanionFrame frame) => _inbound.Writer.WriteAsync(frame);

        public ValueTask<CompanionFrame> ReadSentAsync(CancellationToken cancellationToken) =>
            _outbound.Reader.ReadAsync(cancellationToken);

        public ValueTask DisposeAsync()
        {
            IsConnected = false;
            _inbound.Writer.TryComplete();
            _outbound.Writer.TryComplete();
            return ValueTask.CompletedTask;
        }
    }
}
