using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Channels;
using JTS.WindowsCompanion.Agent;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Security;
using JTS.WindowsCompanion.Transport;
using JTS.WindowsCompanion.Transfers;

namespace JTS.WindowsCompanion.Tests;

public sealed class CompanionAgentTests
{
    [Fact]
    public async Task TransportDiagnosticsAreBoundedAndExcludeResponseContents()
    {
        await using var channel = new InMemoryCompanionChannel();
        var router = new CompanionRequestRouter(new TestAuthorizationGate());
        const string privateValue = "private-response-must-never-be-logged";
        router.Register("companion.test", (_, _) => ValueTask.FromResult<object?>(new { secret = privateValue }));
        var events = new RecordingSecurityEvents();
        var agent = new CompanionAgent(channel, router, events: events);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var execution = agent.RunAsync(cancellation.Token);
        for (ulong sequence = 1; sequence <= 20; sequence++)
        {
            var request = new CompanionRequest(CompanionProtocol.CurrentVersion, Guid.NewGuid(),
                "companion.test", null, null, null, ControlMessageSerializer.ToElement(new { }));
            await channel.InjectAsync(new CompanionFrame(CompanionProtocol.CurrentVersion,
                CompanionFrameType.ControlJson, CompanionFrameFlags.Final, sequence,
                ControlMessageSerializer.Serialize(request)));
            var sent = await channel.ReadSentAsync(cancellation.Token);
            Assert.Contains(privateValue, System.Text.Encoding.UTF8.GetString(sent.Payload.Span));
        }
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => execution);
        var trace = events.Values.Where(value => value.Category == "transport").ToArray();
        Assert.Equal(16, trace.Count(value => value.Action == "send-lock-wait"));
        Assert.Equal(16, trace.Count(value => value.Action == "channel-send-begin"));
        Assert.Equal(16, trace.Count(value => value.Action == "channel-send-complete"));
        Assert.All(trace, value =>
        {
            Assert.Equal("progress", value.Outcome);
            Assert.Null(value.ErrorCode);
            Assert.DoesNotContain(privateValue, value.ToString());
        });
    }

    [Fact]
    public async Task Agent_ReportsConnectedOnlyAfterTheChannelConnects()
    {
        await using var channel = new InMemoryCompanionChannel();
        var router = new CompanionRequestRouter(new TestAuthorizationGate());
        var agent = new CompanionAgent(channel, router);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var notificationCount = 0;

        var execution = agent.RunAsync(
            _ =>
            {
                Assert.True(channel.IsConnected);
                Interlocked.Increment(ref notificationCount);
                cancellation.Cancel();
                return ValueTask.CompletedTask;
            },
            cancellation.Token);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await execution);
        Assert.Equal(1, notificationCount);
    }

    [Fact]
    public async Task Agent_DoesNotReportConnectedWhenChannelConnectFails()
    {
        var channel = new FailingConnectCompanionChannel();
        var router = new CompanionRequestRouter(new TestAuthorizationGate());
        var agent = new CompanionAgent(channel, router);
        var notificationCount = 0;

        await Assert.ThrowsAsync<IOException>(() => agent.RunAsync(
            _ =>
            {
                Interlocked.Increment(ref notificationCount);
                return ValueTask.CompletedTask;
            },
            CancellationToken.None));

        Assert.Equal(0, notificationCount);
    }

    [Fact]
    public async Task Agent_UsesFramedTestTransportAndReturnsSanitizedResponse()
    {
        await using var channel = new InMemoryCompanionChannel();
        var router = new CompanionRequestRouter(new TestAuthorizationGate());
        router.Register("companion.test", (_, _) => ValueTask.FromResult<object?>(new { ready = true }));
        var agent = new CompanionAgent(channel, router);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var execution = agent.RunAsync(cancellation.Token);
        var request = new CompanionRequest(
            CompanionProtocol.CurrentVersion,
            Guid.NewGuid(),
            "companion.test",
            DateTimeOffset.UtcNow.AddMinutes(1).ToUnixTimeMilliseconds(),
            "test-idempotency-key",
            null,
            ControlMessageSerializer.ToElement(new { }));
        await channel.InjectAsync(new CompanionFrame(
            CompanionProtocol.CurrentVersion,
            CompanionFrameType.ControlJson,
            CompanionFrameFlags.Final,
            1,
            ControlMessageSerializer.Serialize(request)));

        var frame = await channel.ReadSentAsync(cancellation.Token);
        var response = ControlMessageSerializer.Deserialize<CompanionResponse>(frame.Payload.Span);
        Assert.True(response.Success);
        Assert.True(response.Result?.GetProperty("ready").GetBoolean());
        Assert.Equal(CompanionFrameType.ControlJson, frame.Type);

        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await execution);
    }

    [Fact]
    public async Task Router_RejectsLogInjectionInMethodName()
    {
        var router = new CompanionRequestRouter(new TestAuthorizationGate());
        var request = new CompanionRequest(
            CompanionProtocol.CurrentVersion,
            Guid.NewGuid(),
            "shell.exec\nsecret=value",
            null,
            null,
            null,
            ControlMessageSerializer.ToElement(new { }));

        var response = await router.DispatchAsync(request, DateTimeOffset.UtcNow, CancellationToken.None);
        Assert.Equal("REQUEST_INVALID", response.Error?.Code);
    }

    [Fact]
    public async Task Agent_DispatchesEmergencyElevationReleaseWhileAnotherRequestIsRunning()
    {
        await using var channel = new InMemoryCompanionChannel();
        var router = new CompanionRequestRouter(new TestAuthorizationGate());
        var slowGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        router.Register("test.slow", async (_, cancellationToken) =>
        {
            await slowGate.Task.WaitAsync(cancellationToken);
            return new { completed = true };
        });
        router.Register("elevation.release", (_, _) =>
            ValueTask.FromResult<object?>(new { released = true }));
        var agent = new CompanionAgent(channel, router);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var execution = agent.RunAsync(cancellation.Token);
        var slowRequest = Request("test.slow");
        var releaseRequest = Request("elevation.release");

        await channel.InjectAsync(Frame(1, slowRequest));
        await channel.InjectAsync(Frame(2, releaseRequest));
        var releaseFrame = await channel.ReadSentAsync(cancellation.Token);
        var releaseResponse = ControlMessageSerializer.Deserialize<CompanionResponse>(releaseFrame.Payload.Span);
        Assert.Equal(releaseRequest.RequestId, releaseResponse.RequestId);
        Assert.True(releaseResponse.Success);

        slowGate.SetResult();
        var slowFrame = await channel.ReadSentAsync(cancellation.Token);
        var slowResponse = ControlMessageSerializer.Deserialize<CompanionResponse>(slowFrame.Payload.Span);
        Assert.Equal(slowRequest.RequestId, slowResponse.RequestId);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await execution);

        static CompanionRequest Request(string method) => new(
            CompanionProtocol.CurrentVersion,
            Guid.NewGuid(),
            method,
            null,
            null,
            null,
            ControlMessageSerializer.ToElement(new { }));

        static CompanionFrame Frame(ulong sequence, CompanionRequest request) => new(
            CompanionProtocol.CurrentVersion,
            CompanionFrameType.ControlJson,
            CompanionFrameFlags.Final,
            sequence,
            ControlMessageSerializer.Serialize(request));
    }

    [Fact]
    public async Task Agent_CancellationControlBypassesTheConcurrentOperationLimit()
    {
        await using var channel = new InMemoryCompanionChannel();
        var router = new CompanionRequestRouter(new TestAuthorizationGate());
        var releaseSlowRequests = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var allStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var started = 0;
        router.Register("test.slow", async (_, cancellationToken) =>
        {
            if (Interlocked.Increment(ref started) == 32)
            {
                allStarted.TrySetResult();
            }

            await releaseSlowRequests.Task.WaitAsync(cancellationToken);
            return new { completed = true };
        });
        var agent = new CompanionAgent(channel, router);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var execution = agent.RunAsync(cancellation.Token);
        for (ulong sequence = 1; sequence <= 32; sequence += 1)
        {
            await channel.InjectAsync(Frame(sequence, Request("test.slow", new { })));
        }

        await allStarted.Task.WaitAsync(cancellation.Token);
        var cancelRequest = Request(
            "companion.cancel",
            new { requestId = Guid.NewGuid() });
        await channel.InjectAsync(Frame(33, cancelRequest));

        var frame = await channel.ReadSentAsync(cancellation.Token);
        var response = ControlMessageSerializer.Deserialize<CompanionResponse>(frame.Payload.Span);
        Assert.Equal(cancelRequest.RequestId, response.RequestId);
        Assert.Equal("PAIRING_REQUIRED", response.Error?.Code);
        Assert.NotEqual("COMPANION_BUSY", response.Error?.Code);

        releaseSlowRequests.TrySetResult();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await execution);

        static CompanionRequest Request(string method, object parameters) => new(
            CompanionProtocol.CurrentVersion,
            Guid.NewGuid(),
            method,
            DateTimeOffset.UtcNow.AddMinutes(1).ToUnixTimeMilliseconds(),
            null,
            null,
            ControlMessageSerializer.ToElement(parameters));

        static CompanionFrame Frame(ulong sequence, CompanionRequest request) => new(
            CompanionProtocol.CurrentVersion,
            CompanionFrameType.ControlJson,
            CompanionFrameFlags.Final,
            sequence,
            ControlMessageSerializer.Serialize(request));
    }

    [Fact]
    public async Task Agent_RejectsBinaryFramesBeforeTransferLookupWhenUnpaired()
    {
        var transferRoot = Path.Combine(
            Path.GetTempPath(),
            $"jts-companion-auth-transfer-{Guid.NewGuid():N}");
        try
        {
            await using var channel = new InMemoryCompanionChannel();
            await using var transfers = new BinaryTransferCoordinator(transferRoot);
            var router = new CompanionRequestRouter(new TestAuthorizationGate(authorized: false));
            var agent = new CompanionAgent(channel, router, transfers: transfers);
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var execution = agent.RunAsync(cancellation.Token);
            var chunk = new BinaryChunk(Guid.NewGuid(), 0, true, "blocked"u8.ToArray());

            await channel.InjectAsync(new CompanionFrame(
                CompanionProtocol.CurrentVersion,
                CompanionFrameType.BinaryChunk,
                CompanionFrameFlags.Final,
                1,
                BinaryChunkCodec.Encode(chunk)));

            var exception = await Assert.ThrowsAsync<CompanionProtocolException>(() => execution);
            Assert.Equal("PAIRING_REQUIRED", exception.Code);
        }
        finally
        {
            if (Directory.Exists(transferRoot))
            {
                Directory.Delete(transferRoot, recursive: true);
            }
        }
    }

    [Fact]
    public async Task Agent_AuthorizationSuccessIsFirstSignedFrameAndUnsignedPostAuthClosesSession()
    {
        await using var channel = new InMemoryCompanionChannel();
        using var windowsIdentity = new AgentTestIdentity();
        using var clientIdentity = new AgentTestIdentity();
        var authorization = new CompanionAuthorizationSession(
            windowsIdentity,
            new AgentMemoryPeerStore(),
            new AgentConsentPrompt());
        var router = new CompanionRequestRouter(authorization);
        var helloChallenge = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
        router.Register("companion.hello", async (_, cancellationToken) =>
            await authorization.BeginHandshakeAsync(helloChallenge, cancellationToken));
        router.Register("companion.authorize", async (request, cancellationToken) =>
            await authorization.AuthorizeAsync(
                request.Parameters.Deserialize<ClientAuthorizationProof>(new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                })!,
                cancellationToken));
        router.Register("companion.state", (_, _) => ValueTask.FromResult<object?>(new { ready = true }));
        var agent = new CompanionAgent(
            channel,
            router,
            frameAuthenticator: new CompanionFrameAuthenticator(windowsIdentity, authorization));
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var execution = agent.RunAsync(cancellation.Token);

        var helloRequest = Request("companion.hello", new { });
        await channel.InjectAsync(Frame(1, helloRequest));
        var helloResponseFrame = await channel.ReadSentAsync(cancellation.Token);
        Assert.False(helloResponseFrame.Flags.HasFlag(CompanionFrameFlags.Authenticated));
        var helloResponse = ControlMessageSerializer.Deserialize<CompanionResponse>(helloResponseFrame.Payload.Span);
        var authorizationChallenge = Convert.FromBase64String(
            helloResponse.Result?.GetProperty("challengeBase64").GetString()!);
        var windowsMetadata = await windowsIdentity.GetMetadataAsync(CancellationToken.None);
        var proof = await ClientAuthorizationProofService.CreateAsync(
            clientIdentity,
            windowsMetadata.DeviceId,
            authorizationChallenge,
            sequence: 2,
            DateTimeOffset.UtcNow,
            CancellationToken.None);

        var authorizeRequest = Request("companion.authorize", proof);
        await channel.InjectAsync(Frame(2, authorizeRequest));
        var authorizeResponseFrame = await channel.ReadSentAsync(cancellation.Token);
        Assert.True(authorizeResponseFrame.Flags.HasFlag(CompanionFrameFlags.Authenticated));
        var binding = CompanionFrameAuthenticator.DeriveSessionBinding(
            windowsMetadata.DeviceId,
            clientIdentity.Metadata.DeviceId,
            helloChallenge,
            authorizationChallenge);
        windowsIdentity.VerifyEnvelope(
            authorizeResponseFrame,
            CompanionFrameDirection.WindowsToMac,
            binding);
        var authorizePayload = authorizeResponseFrame.Payload[CompanionProtocol.FrameAuthenticationEnvelopeBytes..];
        var authorizeResponse = ControlMessageSerializer.Deserialize<CompanionResponse>(authorizePayload.Span);
        Assert.True(authorizeResponse.Success);

        await channel.InjectAsync(Frame(3, Request("companion.state", new { })));
        var exception = await Assert.ThrowsAsync<CompanionProtocolException>(() => execution);
        Assert.Equal("FRAME_AUTH_INVALID", exception.Code);

        static CompanionRequest Request(string method, object parameters) => new(
            CompanionProtocol.CurrentVersion,
            Guid.NewGuid(),
            method,
            DateTimeOffset.UtcNow.AddMinutes(1).ToUnixTimeMilliseconds(),
            null,
            null,
            ControlMessageSerializer.ToElement(parameters));

        static CompanionFrame Frame(ulong sequence, CompanionRequest request) => new(
            CompanionProtocol.CurrentVersion,
            CompanionFrameType.ControlJson,
            CompanionFrameFlags.Final,
            sequence,
            ControlMessageSerializer.Serialize(request));
    }

    private sealed class InMemoryCompanionChannel : ICompanionChannel
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

    private sealed class RecordingSecurityEvents : ISecurityEventSink
    {
        public System.Collections.Concurrent.ConcurrentQueue<SecurityEvent> Values { get; } = new();
        public void Record(SecurityEvent securityEvent) => Values.Enqueue(securityEvent);
    }

    private sealed class FailingConnectCompanionChannel : ICompanionChannel
    {
        public bool IsConnected => false;

        public ValueTask ConnectAsync(CancellationToken cancellationToken) =>
            ValueTask.FromException(new IOException("connect failed"));

        public ValueTask<CompanionFrame> ReceiveAsync(CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public ValueTask SendAsync(CompanionFrame frame, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class AgentTestIdentity : ICompanionIdentity, IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public AgentTestIdentity()
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
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(_key.SignData(
                payload.Span,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        public void VerifyEnvelope(
            CompanionFrame frame,
            CompanionFrameDirection direction,
            byte[] binding)
        {
            Assert.True(frame.Payload.Span[..4].SequenceEqual("JTSA"u8));
            var payload = frame.Payload[CompanionProtocol.FrameAuthenticationEnvelopeBytes..];
            var canonical = CompanionFrameAuthenticator.BuildCanonicalPayload(
                frame.Version,
                direction,
                frame.Type,
                frame.Flags,
                frame.Sequence,
                payload.Span,
                binding);
            Assert.True(_key.VerifyData(
                canonical,
                frame.Payload.Span.Slice(4, 64),
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        }

        public void Dispose() => _key.Dispose();
    }

    private sealed class AgentMemoryPeerStore : ICompanionPeerStore
    {
        private CompanionPeerGrant? _grant;

        public ValueTask<CompanionPeerGrant?> LoadAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(_grant);

        public ValueTask SaveIfAbsentAsync(CompanionPeerGrant grant, CancellationToken cancellationToken)
        {
            _grant ??= grant;
            return ValueTask.CompletedTask;
        }

        public ValueTask ClearAsync(CancellationToken cancellationToken)
        {
            _grant = null;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class AgentConsentPrompt : ICompanionPairingConsentPrompt
    {
        public ValueTask<bool> ConfirmAsync(
            CompanionPeerIdentity peer,
            CancellationToken cancellationToken) => ValueTask.FromResult(true);
    }
}
