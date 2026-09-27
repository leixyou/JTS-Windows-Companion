using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JTS.WindowsCompanion.Agent;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Transfers;
using JTS.WindowsCompanion.Worker;

namespace JTS.WindowsCompanion.Tests;

public sealed class VrcFactoryWorkerBridgeTests : IAsyncLifetime
{
    private const string ExecutableSha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private readonly DirectoryInfo _transferRoot = Directory.CreateTempSubdirectory();
    private readonly BinaryTransferCoordinator _transfers;

    public VrcFactoryWorkerBridgeTests()
    {
        _transfers = new BinaryTransferCoordinator(_transferRoot.FullName);
    }

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        await _transfers.DisposeAsync();
        _transferRoot.Delete(recursive: true);
    }

    [Fact]
    public async Task MethodRegistrar_ReturnsStableNotConfiguredErrorWithoutProvider()
    {
        var router = new CompanionRequestRouter(new TestAuthorizationGate());
        VrcFactoryWorkerMethodRegistrar.Register(router, bridge: null);

        var response = await router.DispatchAsync(
            Request("worker.doctor", new { }),
            DateTimeOffset.UtcNow,
            CancellationToken.None);

        Assert.False(response.Success);
        Assert.Equal("WORKER_NOT_CONFIGURED", response.Error?.Code);
    }

    [Fact]
    public async Task MethodRegistrar_RoutesStatusAndPreservesStructuredWorkerResult()
    {
        var runner = new RecordingRunner(request => JsonResult(new
        {
            ok = true,
            jobId = request.Arguments[2],
            state = "running",
            resultAvailable = false,
        }));
        var router = new CompanionRequestRouter(new TestAuthorizationGate());
        VrcFactoryWorkerMethodRegistrar.Register(router, Bridge(runner));

        var response = await router.DispatchAsync(
            Request("worker.status", new { jobId = "avatar-pilot-001" }),
            DateTimeOffset.UtcNow,
            CancellationToken.None);

        Assert.True(response.Success);
        Assert.Equal("avatar-pilot-001", response.Result?.GetProperty("jobId").GetString());
        Assert.Equal("running", response.Result?.GetProperty("state").GetString());
        Assert.Equal(["status", "--job-id", "avatar-pilot-001"], runner.Requests[0].Arguments);
    }

    [Fact]
    public async Task Submit_UsesPinnedExecutableFixedSubcommandAndVerifiesBundleHash()
    {
        var bundle = Encoding.UTF8.GetBytes("signed-vrc-job-bundle");
        var bundleSha256 = Convert.ToHexString(SHA256.HashData(bundle)).ToLowerInvariant();
        var runner = new RecordingRunner(request =>
        {
            Assert.NotNull(request.StandardInputFilePath);
            Assert.Equal(bundle, File.ReadAllBytes(request.StandardInputFilePath));
            return JsonResult(new
            {
                ok = true,
                jobId = "avatar-pilot-001",
                state = "queued",
                bundleSha256,
            });
        });
        var bridge = Bridge(runner);

        var response = await bridge.ExecuteAsync(
            VrcFactoryWorkerAction.Submit,
            await UploadParametersAsync("avatar-pilot-001", bundle),
            CancellationToken.None);

        Assert.True(Element(response!).GetProperty("ok").GetBoolean());
        var request = Assert.Single(runner.Requests);
        Assert.Equal(WorkerExecutablePath(), request.ExecutablePath);
        Assert.Equal(["submit-stdin"], request.Arguments);
        Assert.True(request.StandardInput.IsEmpty);
        Assert.NotNull(request.StandardInputFilePath);
    }

    [Fact]
    public async Task Status_RejectsTaskProvidedShellExecutableAndArgumentsBeforeLaunchingProcess()
    {
        var runner = new RecordingRunner(_ => throw new InvalidOperationException("must not launch"));
        var bridge = Bridge(runner);

        var failure = await Assert.ThrowsAsync<CompanionProtocolException>(() => bridge.ExecuteAsync(
            VrcFactoryWorkerAction.Status,
            Parameters(new
            {
                jobId = "avatar-pilot-001",
                executable = "cmd.exe",
                shell = "whoami",
                arguments = new[] { "/c", "whoami" },
            }),
            CancellationToken.None).AsTask());

        Assert.Equal("WORKER_REQUEST_INVALID", failure.Code);
        Assert.Empty(runner.Requests);
    }

    [Fact]
    public async Task StatusAndCancel_UseOnlyValidatedJobIdArguments()
    {
        var runner = new RecordingRunner(request => JsonResult(new
        {
            ok = true,
            jobId = request.Arguments[2],
            state = request.Arguments[0] == "cancel" ? "cancel-requested" : "running",
        }));
        var bridge = Bridge(runner);
        var parameters = Parameters(new { jobId = "avatar-pilot-001" });

        await bridge.ExecuteAsync(VrcFactoryWorkerAction.Status, parameters, CancellationToken.None);
        await bridge.ExecuteAsync(VrcFactoryWorkerAction.Cancel, parameters, CancellationToken.None);

        Assert.Equal(["status", "--job-id", "avatar-pilot-001"], runner.Requests[0].Arguments);
        Assert.Equal(["cancel", "--job-id", "avatar-pilot-001"], runner.Requests[1].Arguments);
        Assert.All(runner.Requests, request => Assert.True(request.StandardInput.IsEmpty));
    }

    [Fact]
    public async Task Submit_FailsClosedWhenWorkerReportsDifferentBundleDigest()
    {
        var runner = new RecordingRunner(_ => JsonResult(new
        {
            ok = true,
            jobId = "avatar-pilot-001",
            state = "queued",
            bundleSha256 = new string('b', 64),
        }));
        var bridge = Bridge(runner);
        var bundle = "bundle"u8.ToArray();
        var parameters = await UploadParametersAsync("avatar-pilot-001", bundle);

        var failure = await Assert.ThrowsAsync<CompanionProtocolException>(() => bridge.ExecuteAsync(
            VrcFactoryWorkerAction.Submit,
            parameters,
            CancellationToken.None).AsTask());

        Assert.Equal("WORKER_BUNDLE_HASH_MISMATCH", failure.Code);
    }

    [Fact]
    public async Task Collect_ReturnsBinaryTransferDescriptorAndExactChunkedBundle()
    {
        var bundle = "verified-result-zip"u8.ToArray();
        var runner = new RecordingRunner(request =>
        {
            Assert.NotNull(request.StandardOutputFilePath);
            File.WriteAllBytes(request.StandardOutputFilePath, bundle);
            return new FixedWorkerProcessResult(0, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty);
        });
        var bridge = Bridge(runner);

        var response = Element((await bridge.ExecuteAsync(
            VrcFactoryWorkerAction.Collect,
            Parameters(new { jobId = "avatar-pilot-001" }),
            CancellationToken.None))!);

        Assert.Equal("avatar-pilot-001", response.GetProperty("jobId").GetString());
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(bundle)).ToLowerInvariant(),
            response.GetProperty("bundleSha256").GetString());
        Assert.Equal(["collect-stdout", "--job-id", "avatar-pilot-001"], runner.Requests[0].Arguments);

        var received = new MemoryStream();
        _transfers.BindSender((chunk, _) =>
        {
            Assert.Equal(received.Length, chunk.Offset);
            received.Write(chunk.Data.Span);
            return ValueTask.CompletedTask;
        });
        var transferId = response.GetProperty("transferId").GetGuid();
        await _transfers.SendDownloadAsync(
            Parameters(new { transferId, offset = 0 }),
            CancellationToken.None);
        Assert.Equal(bundle, received.ToArray());
    }

    [Fact]
    public async Task Doctor_RemovesObsoleteTailscaleGateButRequiresEveryLocalWorkerCheck()
    {
        var checks = new[] { "platform", "python", "unity", "vpm", "worker", "spool", "consumer" }
            .Select(name => new { name, ok = true })
            .Cast<object>()
            .Append(new { name = "tailscale", ok = false })
            .ToArray();
        var runner = new RecordingRunner(_ => JsonResult(
            new { ok = false, workerProtocol = "fixed-ssh-v1", checks },
            exitCode: 2));
        var bridge = Bridge(runner);

        var response = Element((await bridge.ExecuteAsync(
            VrcFactoryWorkerAction.Doctor,
            Parameters(new { }),
            CancellationToken.None))!);

        Assert.True(response.GetProperty("ok").GetBoolean());
        Assert.Equal("fixed-dvc-v1", response.GetProperty("workerProtocol").GetString());
        Assert.True(response.GetProperty("worker").GetProperty("ready").GetBoolean());
        Assert.False(response.GetProperty("networkRequirements").GetProperty("tailscale").GetBoolean());
        Assert.DoesNotContain(
            response.GetProperty("checks").EnumerateArray(),
            check => check.GetProperty("name").GetString() == "tailscale");
    }

    [Fact]
    public async Task InstalledExecutableVerifier_RejectsExecutableDigestChange()
    {
        var directory = Directory.CreateTempSubdirectory();
        try
        {
            var executable = Path.Combine(directory.FullName, "vrc-factory-worker.exe");
            await File.WriteAllBytesAsync(executable, "installed-worker"u8.ToArray());
            var verifier = new InstalledExecutableVerifier();

            var failure = await Assert.ThrowsAsync<CompanionProtocolException>(() => verifier.VerifyAsync(
                executable,
                new string('0', 64),
                CancellationToken.None).AsTask());

            Assert.Equal("WORKER_EXECUTABLE_CHANGED", failure.Code);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    private VrcFactoryWorkerBridge Bridge(RecordingRunner runner) => new(
        WorkerExecutablePath(),
        ExecutableSha256,
        _transfers,
        new AcceptingEnvelopeSecurity(),
        runner,
        new AcceptingVerifier());

    private async Task<JsonElement> UploadParametersAsync(string jobId, byte[] bundle)
    {
        var transferId = Guid.NewGuid();
        var sha256 = Convert.ToHexString(SHA256.HashData(bundle)).ToLowerInvariant();
        await _transfers.BeginUploadAsync(
            Parameters(new
            {
                transferId,
                purpose = VrcFactoryWorkerBridge.SubmitTransferPurpose,
                totalBytes = bundle.LongLength,
                sha256,
            }),
            CancellationToken.None);
        await _transfers.AcceptUploadChunkAsync(
            new BinaryChunk(transferId, 0, true, bundle),
            CancellationToken.None);
        await _transfers.FinalizeUploadAsync(
            Parameters(new { transferId }),
            CancellationToken.None);
        return Parameters(new
        {
            jobId,
            transferId,
            totalBytes = bundle.LongLength,
            bundleSha256 = sha256,
            jobEnvelope = TestJobEnvelope(jobId, bundle.LongLength, sha256),
        });
    }

    private static VrcJobEnvelope TestJobEnvelope(string jobId, long totalBytes, string sha256) => new(
        VrcEnvelopeSecurity.JobSchemaVersion,
        Guid.Parse("11111111-1111-4111-8111-111111111111"),
        Guid.Parse("22222222-2222-4222-8222-222222222222"),
        new string('a', 64),
        jobId,
        totalBytes,
        sha256,
        1_700_000_000_000,
        Convert.ToBase64String(new byte[64]));

    private static string WorkerExecutablePath() => Path.Combine(
        Path.GetTempPath(),
        "JTS-WindowsCompanion-tests",
        "vrc-factory-worker.exe");

    private static JsonElement Parameters(object value) => JsonSerializer.SerializeToElement(
        value,
        ControlMessageSerializer.Options);

    private static CompanionRequest Request(string method, object parameters) => new(
        CompanionProtocol.CurrentVersion,
        Guid.NewGuid(),
        method,
        DateTimeOffset.UtcNow.AddMinutes(1).ToUnixTimeMilliseconds(),
        null,
        null,
        Parameters(parameters));

    private static JsonElement Element(object value) => JsonSerializer.SerializeToElement(
        value,
        ControlMessageSerializer.Options);

    private static FixedWorkerProcessResult JsonResult(object value, int exitCode = 0) => new(
        exitCode,
        JsonSerializer.SerializeToUtf8Bytes(value, ControlMessageSerializer.Options),
        ReadOnlyMemory<byte>.Empty);

    private sealed class AcceptingVerifier : IInstalledExecutableVerifier
    {
        public ValueTask VerifyAsync(
            string executablePath,
            string expectedSha256,
            CancellationToken cancellationToken) => ValueTask.CompletedTask;
    }

    private sealed class AcceptingEnvelopeSecurity : IVrcEnvelopeSecurity
    {
        public ValueTask<VrcJobEnvelope> VerifyJobAsync(
            JsonElement envelope,
            string expectedJobId,
            long expectedTotalBytes,
            string expectedBundleSha256,
            CancellationToken cancellationToken) => ValueTask.FromResult(
                TestJobEnvelope(expectedJobId, expectedTotalBytes, expectedBundleSha256));

        public ValueTask<VrcResultEnvelope> SignResultAsync(
            string jobId,
            string state,
            long totalBytes,
            string bundleSha256,
            CancellationToken cancellationToken) => ValueTask.FromResult(new VrcResultEnvelope(
                VrcEnvelopeSecurity.ResultSchemaVersion,
                Guid.Parse("11111111-1111-4111-8111-111111111111"),
                new string('b', 64),
                Guid.Parse("22222222-2222-4222-8222-222222222222"),
                new string('a', 64),
                jobId,
                state,
                totalBytes,
                bundleSha256,
                1_700_000_000_000,
                Convert.ToBase64String(new byte[64])));
    }

    private sealed class RecordingRunner(
        Func<FixedWorkerProcessRequest, FixedWorkerProcessResult> resultFactory)
        : IFixedWorkerProcessRunner
    {
        public List<FixedWorkerProcessRequest> Requests { get; } = [];

        public ValueTask<FixedWorkerProcessResult> RunAsync(
            FixedWorkerProcessRequest request,
            CancellationToken cancellationToken)
        {
            Requests.Add(request);
            return ValueTask.FromResult(resultFactory(request));
        }
    }
}
