using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Elevation;
using JTS.WindowsCompanion.Protocol;

namespace JTS.WindowsCompanion.Tests;

public sealed class ElevationBrokerLeaseCancellationTests
{
    [Fact]
    public async Task BrokerSession_LeaseDeadlineCancelsInFlightExecutionAndReturnsSafeError()
    {
        using var temporary = new TemporaryDirectory();
        var action = new ElevatedPowerShellActionDescriptor(
            "deadline-action",
            "Write-Output ok",
            temporary.Path,
            15 * 60 * 1_000,
            4_096,
            new Dictionary<string, string>(),
            [new ResolvedElevationDataScope("factory", temporary.Path, ElevationScopeAccess.ReadWrite)]);
        var timeProvider = new ManualTimeProvider(DateTimeOffset.UtcNow);
        using var leases = new ElevationLeaseManager(timeProvider);
        var process = new WaitingProcess();
        var executor = new ElevatedPowerShellExecutor(
            new FixedElevationVerifier(),
            new FixedProcessFactory(process),
            timeProvider);
        var session = new ElevationBrokerSession(leases, executor);
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
        var accepting = server.WaitForConnectionAsync(timeout.Token);
        await client.ConnectAsync(timeout.Token);
        await accepting;
        var brokerTask = session.RunAsync(server, nonce, 42, timeout.Token);

        _ = await LocalIpcJsonCodec.ReadAsync<ElevationBrokerMessage>(client, timeout.Token);
        var openId = Guid.NewGuid();
        await LocalIpcJsonCodec.WriteAsync(
            client,
            Message(
                openId,
                ElevationBrokerMessageKind.OpenLease,
                nonce,
                new ElevationBrokerOpenLease(action, 1_000)),
            timeout.Token);
        var opened = await LocalIpcJsonCodec.ReadAsync<ElevationBrokerMessage>(client, timeout.Token);
        var lease = opened.Payload.Deserialize<ElevationLease>(ControlMessageSerializer.Options);
        Assert.NotNull(lease);

        var executeId = Guid.NewGuid();
        await LocalIpcJsonCodec.WriteAsync(
            client,
            Message(
                executeId,
                ElevationBrokerMessageKind.Execute,
                nonce,
                new ElevationBrokerExecute(lease.LeaseId, action.ActionId, action)),
            timeout.Token);
        await process.WaitStarted.Task.WaitAsync(timeout.Token);

        timeProvider.Advance(TimeSpan.FromSeconds(1));

        var response = await LocalIpcJsonCodec.ReadAsync<ElevationBrokerMessage>(client, timeout.Token);
        Assert.Equal(ElevationBrokerMessageKind.Error, response.Kind);
        var error = response.Payload.Deserialize<ElevationBrokerError>(ControlMessageSerializer.Options);
        Assert.Equal("LEASE_EXPIRED", error?.Code);
        Assert.Equal(1, process.TerminationCount);
        await client.DisposeAsync();
        await brokerTask;
    }

    private static ElevationBrokerMessage Message<T>(
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

    private sealed class FixedProcessFactory : IContainedProcessFactory
    {
        private readonly WaitingProcess _process;

        public FixedProcessFactory(WaitingProcess process)
        {
            _process = process;
        }

        public IContainedProcess Create(ProcessStartInfo startInfo) => _process;
    }

    private sealed class WaitingProcess : IContainedProcess
    {
        private readonly TaskCompletionSource _exit = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource WaitStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TextReader StandardOutput { get; } = new StringReader(string.Empty);

        public TextReader StandardError { get; } = new StringReader(string.Empty);

        public bool HasExited { get; private set; }

        public int ExitCode => -1;

        public int TerminationCount { get; private set; }

        public ValueTask StartAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.CompletedTask;
        }

        public ValueTask WriteStandardInputAsync(
            ReadOnlyMemory<char> text,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.CompletedTask;
        }

        public async Task WaitForExitAsync(CancellationToken cancellationToken)
        {
            WaitStarted.TrySetResult();
            await _exit.Task.WaitAsync(cancellationToken);
        }

        public ValueTask TerminateAsync()
        {
            if (!HasExited)
            {
                TerminationCount++;
                HasExited = true;
                _exit.TrySetResult();
            }

            return ValueTask.CompletedTask;
        }

        public async ValueTask DisposeAsync()
        {
            if (!HasExited)
            {
                await TerminateAsync();
            }

            StandardOutput.Dispose();
            StandardError.Dispose();
        }
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"jts-broker-deadline-{Guid.NewGuid():N}");
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
