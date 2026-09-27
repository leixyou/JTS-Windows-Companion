using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Elevation;
using JTS.WindowsCompanion.Files;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Shell;

namespace JTS.WindowsCompanion.Tests;

public sealed class ElevationBrokerTests
{
    [Fact]
    public void ActionBuilder_BindsFullScriptDirectoryScopesAndExecutionPayload()
    {
        using var temporary = new TemporaryDirectory();
        var work = Path.Combine(temporary.Path, "work");
        Directory.CreateDirectory(work);
        var sandbox = new FileSandbox([new FileRoot("factory", temporary.Path)]);
        var builder = new ElevationActionBuilder(sandbox);
        var request = new PowerShellElevationRequest(
            new ShellExecutionRequest(
                "Set-Content -LiteralPath result.txt -Value ok",
                "factory",
                "work",
                TimeoutMilliseconds: 5_000,
                MaximumOutputBytes: 8_192,
                Environment: new Dictionary<string, string> { ["JTS_JOB_ID"] = "avatar-pilot-001" },
                RequiresElevation: true),
            DurationMilliseconds: 5 * 60 * 1000,
            [new ElevationDataScope("factory", ".", ElevationScopeAccess.ReadWrite)]);

        var (action, duration) = builder.Build(request);
        Assert.Equal(TimeSpan.FromMinutes(5), duration);
        Assert.Equal(request.Execution.Script, action.Script);
        Assert.Equal(work, action.WorkingDirectory);
        Assert.Equal(64, action.PayloadSha256.Length);

        var execution = request.Execution with
        {
            ElevationLeaseId = Guid.NewGuid(),
            ElevationActionId = action.ActionId,
        };
        Assert.Equal(action.CanonicalPayload, builder.RebuildForExecution(execution, action).CanonicalPayload);
        Assert.Throws<UnauthorizedAccessException>(() => builder.RebuildForExecution(
            execution with { Script = "Remove-Item -Recurse C:\\" },
            action));
        Assert.Throws<ArgumentException>(() => builder.Build(request with { DurationMilliseconds = 15 * 60 * 1000 + 1 }));
    }

    [Fact]
    public async Task BrokerSession_OpensReportsAndReleasesExactLeaseOverFramedPipe()
    {
        using var temporary = new TemporaryDirectory();
        var work = Path.Combine(temporary.Path, "work");
        Directory.CreateDirectory(work);
        var action = new ElevatedPowerShellActionDescriptor(
            "approved-action",
            "Write-Output ok",
            work,
            1_000,
            4_096,
            new Dictionary<string, string>(),
            [new ResolvedElevationDataScope("factory", temporary.Path, ElevationScopeAccess.ReadWrite)]);
        var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var pipeName = $"e{Guid.NewGuid():N}";
        await using var server = new NamedPipeServerStream(
            pipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        await using var client = new NamedPipeClientStream(
            ".",
            pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var accept = server.WaitForConnectionAsync(timeout.Token);
        await client.ConnectAsync(timeout.Token);
        await accept;
        var session = new ElevationBrokerSession(
            new ElevationLeaseManager(),
            new ElevatedPowerShellExecutor(new FixedElevationVerifier()));
        var serverTask = session.RunAsync(server, nonce, 42, timeout.Token);

        var hello = await LocalIpcJsonCodec.ReadAsync<ElevationBrokerMessage>(client, timeout.Token);
        Assert.Equal(ElevationBrokerMessageKind.Hello, hello.Kind);
        var openId = Guid.NewGuid();
        await LocalIpcJsonCodec.WriteAsync(
            client,
            BrokerMessage(openId, ElevationBrokerMessageKind.OpenLease, nonce, new ElevationBrokerOpenLease(action, 60_000)),
            timeout.Token);
        var opened = await LocalIpcJsonCodec.ReadAsync<ElevationBrokerMessage>(client, timeout.Token);
        var lease = opened.Payload.Deserialize<ElevationLease>(ControlMessageSerializer.Options);
        Assert.NotNull(lease);
        Assert.Equal(action.PayloadSha256, lease.Actions.Single().PayloadSha256);

        var statusId = Guid.NewGuid();
        await LocalIpcJsonCodec.WriteAsync(
            client,
            BrokerMessage(statusId, ElevationBrokerMessageKind.Status, nonce, new ElevationBrokerLeaseId(lease.LeaseId)),
            timeout.Token);
        var status = await LocalIpcJsonCodec.ReadAsync<ElevationBrokerMessage>(client, timeout.Token);
        Assert.Equal(ElevationBrokerMessageKind.LeaseStatus, status.Kind);

        var releaseId = Guid.NewGuid();
        await LocalIpcJsonCodec.WriteAsync(
            client,
            BrokerMessage(releaseId, ElevationBrokerMessageKind.Release, nonce, new ElevationBrokerLeaseId(lease.LeaseId)),
            timeout.Token);
        var released = await LocalIpcJsonCodec.ReadAsync<ElevationBrokerMessage>(client, timeout.Token);
        Assert.Equal(ElevationBrokerMessageKind.Released, released.Kind);
        await serverTask;
    }

    [Fact]
    public async Task LocalIpcCodec_RejectsOversizedAndTruncatedFrames()
    {
        await using var oversized = new MemoryStream();
        await Assert.ThrowsAsync<InvalidDataException>(async () => await LocalIpcJsonCodec.WriteAsync(
            oversized,
            new string('x', LocalIpcJsonCodec.MaximumPayloadBytes + 1),
            CancellationToken.None));

        await using var truncated = new MemoryStream([0, 0, 0, 10, 1, 2, 3]);
        await Assert.ThrowsAsync<EndOfStreamException>(async () =>
            await LocalIpcJsonCodec.ReadAsync<object>(truncated, CancellationToken.None));
    }

    private static ElevationBrokerMessage BrokerMessage<T>(
        Guid id,
        ElevationBrokerMessageKind kind,
        string nonce,
        T payload) => new(
            ElevationBrokerSession.ProtocolVersion,
            id,
            kind,
            nonce,
            ControlMessageSerializer.ToElement(payload));

    private sealed class FixedElevationVerifier : IProcessElevationVerifier
    {
        public bool IsElevated => true;
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"jts-elevation-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
