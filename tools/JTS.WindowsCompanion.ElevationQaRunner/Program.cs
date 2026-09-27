using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Elevation;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Security;
using JTS.WindowsCompanion.Shell;
using JTS.WindowsCompanion.Windows.Elevation;
using JTS.WindowsCompanion.Windows.Security;

namespace JTS.WindowsCompanion.ElevationQaRunner;

internal static class Program
{
    private const string EvidenceFileName = "elevation-protocol-qa.json";
    private const string DiagnosticReleasePrefix = "qa-elevation-";

    public static async Task<int> Main(string[] arguments)
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10))
        {
            Console.Error.WriteLine("The manifest-verified elevation QA runner requires Windows 10 or Windows 11.");
            return 2;
        }

        try
        {
            await RunAsync(Options.Parse(arguments)).ConfigureAwait(false);
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(
                "The manifest-verified elevation QA runner failed: {0}",
                exception.GetType().Name);
            return 1;
        }
    }

    private static async Task RunAsync(Options options)
    {
        using var overallDeadline = new CancellationTokenSource(TimeSpan.FromMinutes(6));
        var cancellationToken = overallDeadline.Token;
        var runnerPath = Path.GetFullPath(
            Environment.ProcessPath
            ?? throw new InvalidOperationException("The runner executable path is unavailable."));
        if (!string.Equals(
                Path.GetFileName(runnerPath),
                "JTS.WindowsCompanion.Agent.exe",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The QA runner must retain the production Agent peer filename.");
        }

        AssertRegularDirectory(options.WorkingDirectory, "working directory");
        Directory.CreateDirectory(options.EvidenceDirectory);
        AssertRegularDirectory(options.EvidenceDirectory, "evidence directory");
        var evidencePath = Path.Combine(options.EvidenceDirectory, EvidenceFileName);
        if (File.Exists(evidencePath))
        {
            throw new IOException("The elevation QA evidence file already exists.");
        }

        // Publish this exact-name runner and a QA-only Broker with a separate
        // diagnostic key. Neither the production key nor a caller-supplied
        // runtime key may authorize this test runner as the production Agent.
        var release = ReleaseManifestTrust.LoadForExecutable(runnerPath);
        if (!release.ReleaseId.StartsWith(DiagnosticReleasePrefix, StringComparison.Ordinal))
        {
            throw new UnauthorizedAccessException("The elevation QA requires a diagnostic-only release manifest.");
        }
        var brokerRelease = ReleaseManifestTrust.LoadForExecutable(options.BrokerExecutable);
        if (!string.Equals(release.PayloadSha256, brokerRelease.PayloadSha256, StringComparison.Ordinal))
        {
            throw new UnauthorizedAccessException("The QA runner and Broker must use the same authenticated diagnostic release.");
        }
        var verifier = new ReleaseManifestExecutableTrustVerifier(release);
        using var runnerFileLock = verifier.OpenVerifiedFile(runnerPath, "JTS.WindowsCompanion.Agent.exe");

        var runId = Guid.NewGuid().ToString("N");
        var counterPath = Path.Combine(options.WorkingDirectory, $"exact-count-{runId}.txt");
        var scriptTamperMarker = Path.Combine(
            options.WorkingDirectory,
            $"script-tamper-{runId}.txt");
        var alternateDirectory = Path.Combine(options.WorkingDirectory, $"path-tamper-{runId}");
        Directory.CreateDirectory(alternateDirectory);
        var alternateCounterPath = Path.Combine(
            alternateDirectory,
            Path.GetFileName(counterPath));
        var action = new ElevatedPowerShellActionDescriptor(
            $"qa-exact-{runId}",
            CounterScript(Path.GetFileName(counterPath)),
            options.WorkingDirectory,
            30_000,
            8_192,
            new Dictionary<string, string>(),
            [
                new ResolvedElevationDataScope(
                    "qa",
                    options.WorkingDirectory,
                    ElevationScopeAccess.ReadWrite),
            ]);

        var tamperEvidence = new List<object>();
        int exactBrokerProcessId;
        Guid exactLeaseId;
        FileEvidence exactBrokerEvidence;
        int exactBrokerExitCode;
        await using (var connection = await BrokerConnection.OpenAsync(
                         options.BrokerExecutable,
                         verifier,
                         action,
                         durationMilliseconds: 120_000,
                         cancellationToken).ConfigureAwait(false))
        {
            exactBrokerProcessId = connection.ProcessId;
            exactLeaseId = connection.Lease.LeaseId;
            exactBrokerEvidence = connection.BrokerEvidence;
            var result = await connection.ExecuteAsync(action, cancellationToken)
                .ConfigureAwait(false);
            if (result.ExitCode != 0 || result.TimedOut || result.OutputTruncated)
            {
                throw new InvalidOperationException("The exact approved payload did not complete cleanly.");
            }

            AssertCounterUnchanged(counterPath, expected: "1");

            var tamperedActions = new (string Field, ElevatedPowerShellActionDescriptor Action)[]
            {
                (
                    "script",
                    action with
                    {
                        Script = action.Script
                            + Environment.NewLine
                            + $"[IO.File]::WriteAllText('{PowerShellLiteral(scriptTamperMarker)}', 'executed')",
                    }),
                (
                    "path",
                    action with { WorkingDirectory = alternateDirectory }),
                (
                    "scope",
                    action with
                    {
                        DataScopes =
                        [
                            action.DataScopes[0] with { Access = ElevationScopeAccess.Read },
                        ],
                    }),
                (
                    "timeout",
                    action with { TimeoutMilliseconds = action.TimeoutMilliseconds + 1_000 }),
            };

            foreach (var tampered in tamperedActions)
            {
                var code = await connection.ExecuteForErrorAsync(
                        tampered.Action,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (!string.Equals(code, "NOT_AUTHORIZED", StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        $"The {tampered.Field} mutation returned {code} instead of NOT_AUTHORIZED.");
                }

                AssertCounterUnchanged(counterPath, expected: "1");
                if (File.Exists(scriptTamperMarker) || File.Exists(alternateCounterPath))
                {
                    throw new UnauthorizedAccessException(
                        $"The {tampered.Field} mutation changed a protected marker.");
                }

                tamperEvidence.Add(new
                {
                    field = tampered.Field,
                    errorCode = code,
                    markerUnchanged = true,
                });
            }

            await connection.ReleaseAsync(cancellationToken).ConfigureAwait(false);
            exactBrokerExitCode = connection.NaturalExitCode
                ?? throw new InvalidOperationException(
                    "The exact-payload broker did not record a natural exit.");
        }

        var startedMarker = Path.Combine(options.WorkingDirectory, $"expiry-started-{runId}.txt");
        var completedMarker = Path.Combine(options.WorkingDirectory, $"expiry-completed-{runId}.txt");
        var expiryAction = new ElevatedPowerShellActionDescriptor(
            $"qa-expiry-{runId}",
            $"[IO.File]::WriteAllText('{PowerShellLiteral(startedMarker)}', 'started'); "
            + "Start-Sleep -Seconds 300; "
            + $"[IO.File]::WriteAllText('{PowerShellLiteral(completedMarker)}', 'completed')",
            options.WorkingDirectory,
            10 * 60 * 1_000,
            8_192,
            new Dictionary<string, string>(),
            action.DataScopes);

        int expiryBrokerProcessId;
        Guid expiryLeaseId;
        FileEvidence expiryBrokerEvidence;
        int expiryBrokerExitCode;
        await using (var connection = await BrokerConnection.OpenAsync(
                         options.BrokerExecutable,
                         verifier,
                         expiryAction,
                         options.ExpiryMilliseconds,
                         cancellationToken).ConfigureAwait(false))
        {
            expiryBrokerProcessId = connection.ProcessId;
            expiryLeaseId = connection.Lease.LeaseId;
            expiryBrokerEvidence = connection.BrokerEvidence;
            var code = await connection.ExecuteForErrorAsync(
                    expiryAction,
                    cancellationToken)
                .ConfigureAwait(false);
            if (!string.Equals(code, "LEASE_EXPIRED", StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"The active expiry returned {code} instead of LEASE_EXPIRED.");
            }

            if (!File.Exists(startedMarker)
                || !string.Equals(
                    File.ReadAllText(startedMarker),
                    "started",
                    StringComparison.Ordinal)
                || File.Exists(completedMarker))
            {
                throw new InvalidOperationException(
                    "The expiry marker sequence does not prove bounded in-flight cancellation.");
            }

            await connection.ReleaseAsync(cancellationToken).ConfigureAwait(false);
            expiryBrokerExitCode = connection.NaturalExitCode
                ?? throw new InvalidOperationException(
                    "The expiry broker did not record a natural exit.");
        }

        if (!exactBrokerEvidence.SameContentAs(expiryBrokerEvidence))
        {
            throw new InvalidOperationException(
                "The locked broker image changed between independently verified sessions.");
        }

        var evidence = new
        {
            schemaVersion = 3,
            runId,
            completedAtUtc = DateTimeOffset.UtcNow,
            trust = new
            {
                mechanism = "project-p256-release-manifest",
                releaseId = release.ReleaseId,
                manifestPayloadSha256 = release.PayloadSha256.ToLowerInvariant(),
                diagnosticOnly = true,
            },
            runner = FileEvidence.Create(runnerFileLock, runnerPath),
            broker = exactBrokerEvidence,
            brokerVerificationCount = 2,
            exactPayload = new
            {
                leaseId = exactLeaseId,
                brokerProcessId = exactBrokerProcessId,
                actionId = action.ActionId,
                payloadSha256 = action.PayloadSha256.ToLowerInvariant(),
                executionCount = 1,
                markerObserved = true,
                markerValue = "1",
                brokerManifestVerifiedWhileLocked = true,
                brokerExitedNaturally = true,
                brokerExitCode = exactBrokerExitCode,
            },
            tamperChecks = tamperEvidence,
            expiry = new
            {
                leaseId = expiryLeaseId,
                brokerProcessId = expiryBrokerProcessId,
                durationMilliseconds = options.ExpiryMilliseconds,
                errorCode = "LEASE_EXPIRED",
                startedMarkerObserved = true,
                completedMarkerAbsent = true,
                brokerManifestVerifiedWhileLocked = true,
                brokerExitedNaturally = true,
                brokerExitCode = expiryBrokerExitCode,
            },
        };
        await using var evidenceStream = new FileStream(
            evidencePath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None);
        await JsonSerializer.SerializeAsync(
            evidenceStream,
            evidence,
            new JsonSerializerOptions { WriteIndented = true },
            cancellationToken).ConfigureAwait(false);
        Console.WriteLine(evidencePath);
    }

    private static string CounterScript(string fileName) =>
        $"$p = Join-Path (Get-Location) '{PowerShellLiteral(fileName)}'; "
        + "$n = if (Test-Path -LiteralPath $p) { [int][IO.File]::ReadAllText($p) + 1 } else { 1 }; "
        + "[IO.File]::WriteAllText($p, [string]$n)";

    private static string PowerShellLiteral(string value) =>
        value.Replace("'", "''", StringComparison.Ordinal);

    private static void AssertCounterUnchanged(string path, string expected)
    {
        if (!File.Exists(path)
            || !string.Equals(File.ReadAllText(path), expected, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("The exact-payload execution counter changed unexpectedly.");
        }
    }

    private static void AssertRegularDirectory(string path, string description)
    {
        if (!Directory.Exists(path)
            || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException($"The {description} must be an existing non-reparse directory.");
        }
    }

    private sealed record Options(
        string BrokerExecutable,
        string WorkingDirectory,
        string EvidenceDirectory,
        int ExpiryMilliseconds)
    {
        public static Options Parse(string[] arguments)
        {
            var values = new Dictionary<string, string>(StringComparer.Ordinal);
            if (arguments.Length is < 6 or > 8 || arguments.Length % 2 != 0)
            {
                throw new ArgumentException("The runner arguments are incomplete.");
            }

            for (var index = 0; index < arguments.Length; index += 2)
            {
                if (arguments[index] is not (
                        "--broker"
                        or "--working-directory"
                        or "--evidence-directory"
                        or "--expiry-ms")
                    || !values.TryAdd(arguments[index], arguments[index + 1]))
                {
                    throw new ArgumentException("The runner arguments are malformed.");
                }
            }

            var broker = Path.GetFullPath(Required(values, "--broker"));
            var working = Path.GetFullPath(Required(values, "--working-directory"));
            var evidence = Path.GetFullPath(Required(values, "--evidence-directory"));
            var expiry = values.TryGetValue("--expiry-ms", out var rawExpiry)
                && int.TryParse(rawExpiry, out var parsedExpiry)
                    ? parsedExpiry
                    : 5_000;
            if (!File.Exists(broker)
                || !string.Equals(
                    Path.GetFileName(broker),
                    "JTS.WindowsCompanion.UacBroker.exe",
                    StringComparison.OrdinalIgnoreCase)
                || (File.GetAttributes(broker) & FileAttributes.ReparsePoint) != 0
                || expiry is < 3_000 or > 30_000)
            {
                throw new ArgumentException("The broker path or expiry duration is invalid.");
            }

            return new Options(broker, working, evidence, expiry);
        }

        private static string Required(
            IReadOnlyDictionary<string, string> values,
            string key) =>
            values.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
                ? value
                : throw new ArgumentException($"The required runner argument {key} is missing.");
    }

    private sealed record FileEvidence(
        string Path,
        long LengthBytes,
        string Sha256)
    {
        public static FileEvidence Create(FileStream lockedFile, string path)
        {
            ArgumentNullException.ThrowIfNull(lockedFile);
            if (!lockedFile.CanRead || !lockedFile.CanSeek || lockedFile.Length <= 0)
            {
                throw new IOException("The locked broker image is not a readable regular file.");
            }

            var originalPosition = lockedFile.Position;
            try
            {
                lockedFile.Position = 0;
                var digest = SHA256.HashData(lockedFile);
                return new FileEvidence(
                    System.IO.Path.GetFullPath(path),
                    lockedFile.Length,
                    Convert.ToHexString(digest).ToLowerInvariant());
            }
            finally
            {
                lockedFile.Position = originalPosition;
            }
        }

        public bool SameContentAs(FileEvidence other) =>
            other is not null
            && LengthBytes == other.LengthBytes
            && string.Equals(Sha256, other.Sha256, StringComparison.Ordinal);
    }

    private sealed class BrokerConnection : IAsyncDisposable
    {
        private readonly FileStream _brokerLock;
        private readonly NamedPipeServerStream _pipe;
        private readonly EventWaitHandle _cancellationEvent;
        private readonly Process _process;
        private readonly string _nonce;
        private int _released;

        private BrokerConnection(
            FileStream brokerLock,
            NamedPipeServerStream pipe,
            EventWaitHandle cancellationEvent,
            Process process,
            string nonce,
            ElevationLease lease)
        {
            _brokerLock = brokerLock;
            _pipe = pipe;
            _cancellationEvent = cancellationEvent;
            _process = process;
            _nonce = nonce;
            Lease = lease;
        }

        public int ProcessId => _process.Id;

        public ElevationLease Lease { get; }

        public FileEvidence BrokerEvidence { get; private init; } = null!;

        public int? NaturalExitCode { get; private set; }

        public static async ValueTask<BrokerConnection> OpenAsync(
            string brokerExecutable,
            IReleaseExecutableTrustVerifier verifier,
            ElevatedPowerShellActionDescriptor action,
            int durationMilliseconds,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(verifier);
            var fullBrokerPath = Path.GetFullPath(brokerExecutable);
            AssertRegularBrokerPath(fullBrokerPath);
            var brokerLock = verifier.OpenVerifiedFile(fullBrokerPath, "JTS.WindowsCompanion.UacBroker.exe");
            FileEvidence brokerEvidence;
            try
            {
                AssertRegularBrokerPath(fullBrokerPath);
                brokerEvidence = FileEvidence.Create(brokerLock, fullBrokerPath);
                if (!brokerEvidence.SameContentAs(FileEvidence.Create(brokerLock, fullBrokerPath)))
                {
                    throw new UnauthorizedAccessException(
                        "The manifest-verified broker image changed while locked.");
                }
            }
            catch
            {
                brokerLock.Dispose();
                throw;
            }

            var pipeName = $"JTS.Terminal.Elevation.QA.{Guid.NewGuid():N}";
            var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            var cancellationEventName =
                $"Local\\JTS.Terminal.Elevation.Cancel.{Guid.NewGuid():N}";
            EventWaitHandle cancellationEvent;
            try
            {
                cancellationEvent = new EventWaitHandle(
                    false,
                    EventResetMode.ManualReset,
                    cancellationEventName);
            }
            catch
            {
                brokerLock.Dispose();
                throw;
            }

            NamedPipeServerStream pipe;
            try
            {
                pipe = new NamedPipeServerStream(
                    pipeName,
                    PipeDirection.InOut,
                    1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
                    64 * 1024,
                    64 * 1024);
            }
            catch
            {
                cancellationEvent.Dispose();
                brokerLock.Dispose();
                throw;
            }
            Process? process = null;
            var handedOff = false;
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = fullBrokerPath,
                    UseShellExecute = true,
                    Verb = "runas",
                };
                startInfo.ArgumentList.Add("--pipe");
                startInfo.ArgumentList.Add(pipeName);
                startInfo.ArgumentList.Add("--nonce");
                startInfo.ArgumentList.Add(nonce);
                startInfo.ArgumentList.Add("--cancel-event");
                startInfo.ArgumentList.Add(cancellationEventName);
                process = Process.Start(startInfo)
                    ?? throw new InvalidOperationException("Windows did not start the UAC broker.");

                using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(
                    cancellationToken,
                    timeout.Token);
                await pipe.WaitForConnectionAsync(linked.Token).ConfigureAwait(false);
                if (NamedPipePeerProcess.GetClientProcessId(pipe) != process.Id)
                {
                    throw new UnauthorizedAccessException(
                        "The elevation pipe peer is not the launched broker.");
                }

                var hello = await LocalIpcJsonCodec.ReadAsync<ElevationBrokerMessage>(
                    pipe,
                    linked.Token).ConfigureAwait(false);
                ValidateMessage(hello, ElevationBrokerMessageKind.Hello, nonce, hello.MessageId);
                var helloPayload = Deserialize<BrokerHello>(hello.Payload);
                if (!helloPayload.Elevated || helloPayload.ProcessId != process.Id)
                {
                    throw new InvalidDataException("The broker hello identity is invalid.");
                }

                var openId = Guid.NewGuid();
                await LocalIpcJsonCodec.WriteAsync(
                    pipe,
                    Message(
                        openId,
                        ElevationBrokerMessageKind.OpenLease,
                        nonce,
                        new ElevationBrokerOpenLease(action, durationMilliseconds)),
                    linked.Token).ConfigureAwait(false);
                var opened = await LocalIpcJsonCodec.ReadAsync<ElevationBrokerMessage>(
                    pipe,
                    linked.Token).ConfigureAwait(false);
                ValidateMessage(opened, ElevationBrokerMessageKind.LeaseOpened, nonce, openId);
                var lease = Deserialize<ElevationLease>(opened.Payload);
                var grant = lease.Actions.SingleOrDefault();
                if (lease.LeaseId == Guid.Empty
                    || grant is null
                    || grant.ActionId != action.ActionId
                    || !string.Equals(
                        grant.PayloadSha256,
                        action.PayloadSha256,
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException("The broker returned a detached lease.");
                }

                var connection = new BrokerConnection(
                    brokerLock,
                    pipe,
                    cancellationEvent,
                    process,
                    nonce,
                    lease)
                {
                    BrokerEvidence = brokerEvidence,
                };
                handedOff = true;
                process = null;
                return connection;
            }
            finally
            {
                if (!handedOff)
                {
                    try
                    {
                        _ = cancellationEvent.Set();
                    }
                    finally
                    {
                        try
                        {
                            pipe.Dispose();
                        }
                        finally
                        {
                            try
                            {
                                if (process is not null)
                                {
                                    await StopProcessForCleanupAsync(process)
                                        .ConfigureAwait(false);
                                }
                            }
                            finally
                            {
                                process?.Dispose();
                                cancellationEvent.Dispose();
                                brokerLock.Dispose();
                            }
                        }
                    }
                }
            }
        }

        public async ValueTask<ShellExecutionResult> ExecuteAsync(
            ElevatedPowerShellActionDescriptor action,
            CancellationToken cancellationToken)
        {
            var response = await ExchangeAsync(
                ElevationBrokerMessageKind.Execute,
                new ElevationBrokerExecute(Lease.LeaseId, action.ActionId, action),
                cancellationToken).ConfigureAwait(false);
            ValidateMessageKind(response, ElevationBrokerMessageKind.ExecutionResult);
            return Deserialize<ShellExecutionResult>(response.Payload);
        }

        public async ValueTask<string> ExecuteForErrorAsync(
            ElevatedPowerShellActionDescriptor action,
            CancellationToken cancellationToken)
        {
            var response = await ExchangeAsync(
                ElevationBrokerMessageKind.Execute,
                new ElevationBrokerExecute(Lease.LeaseId, action.ActionId, action),
                cancellationToken).ConfigureAwait(false);
            ValidateMessageKind(response, ElevationBrokerMessageKind.Error);
            return Deserialize<ElevationBrokerError>(response.Payload).Code;
        }

        public async ValueTask ReleaseAsync(CancellationToken cancellationToken)
        {
            if (Interlocked.Exchange(ref _released, 1) != 0)
            {
                return;
            }

            var response = await ExchangeAsync(
                ElevationBrokerMessageKind.Release,
                new ElevationBrokerLeaseId(Lease.LeaseId),
                cancellationToken).ConfigureAwait(false);
            ValidateMessageKind(response, ElevationBrokerMessageKind.Released);
            NaturalExitCode = await WaitForNaturalExitAsync(_process).ConfigureAwait(false);
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                _ = _cancellationEvent.Set();
            }
            finally
            {
                try
                {
                    _pipe.Dispose();
                }
                finally
                {
                    try
                    {
                        await StopProcessForCleanupAsync(_process).ConfigureAwait(false);
                    }
                    finally
                    {
                        _process.Dispose();
                        _cancellationEvent.Dispose();
                        _brokerLock.Dispose();
                    }
                }
            }
        }

        private async ValueTask<ElevationBrokerMessage> ExchangeAsync<T>(
            ElevationBrokerMessageKind kind,
            T payload,
            CancellationToken cancellationToken)
        {
            var messageId = Guid.NewGuid();
            await LocalIpcJsonCodec.WriteAsync(
                _pipe,
                Message(messageId, kind, _nonce, payload),
                cancellationToken).ConfigureAwait(false);
            var response = await LocalIpcJsonCodec.ReadAsync<ElevationBrokerMessage>(
                _pipe,
                cancellationToken).ConfigureAwait(false);
            ValidateMessage(response, response.Kind, _nonce, messageId);
            return response;
        }

        private static async Task<int> WaitForNaturalExitAsync(Process process)
        {
            if (!process.HasExited)
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                try
                {
                    await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (timeout.IsCancellationRequested)
                {
                    await KillProcessForCleanupAsync(process).ConfigureAwait(false);
                    throw new InvalidOperationException(
                        "The released UAC broker did not exit naturally within five seconds.");
                }
            }

            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException(
                    $"The released UAC broker exited naturally with code {process.ExitCode}.");
            }

            return process.ExitCode;
        }

        private static async Task StopProcessForCleanupAsync(Process process)
        {
            if (process.HasExited)
            {
                return;
            }

            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try
            {
                await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested)
            {
                await KillProcessForCleanupAsync(process).ConfigureAwait(false);
            }
        }

        private static async Task KillProcessForCleanupAsync(Process process)
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync().ConfigureAwait(false);
            }
        }

        private static void AssertRegularBrokerPath(string path)
        {
            if (!File.Exists(path)
                || (File.GetAttributes(path) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0
                || !string.Equals(
                    Path.GetFileName(path),
                    "JTS.WindowsCompanion.UacBroker.exe",
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new UnauthorizedAccessException(
                    "The UAC broker must be a regular, non-reparse diagnostic broker file.");
            }
        }

        private static ElevationBrokerMessage Message<T>(
            Guid messageId,
            ElevationBrokerMessageKind kind,
            string nonce,
            T payload) => new(
            ElevationBrokerSession.ProtocolVersion,
            messageId,
            kind,
            nonce,
            ControlMessageSerializer.ToElement(payload));

        private static void ValidateMessage(
            ElevationBrokerMessage message,
            ElevationBrokerMessageKind kind,
            string nonce,
            Guid messageId)
        {
            if (message.Version != ElevationBrokerSession.ProtocolVersion
                || message.MessageId != messageId
                || message.Kind != kind
                || !string.Equals(message.Nonce, nonce, StringComparison.Ordinal))
            {
                throw new InvalidDataException("The broker protocol response is invalid.");
            }
        }

        private static void ValidateMessageKind(
            ElevationBrokerMessage message,
            ElevationBrokerMessageKind kind)
        {
            if (message.Kind != kind)
            {
                throw new InvalidDataException(
                    $"The broker returned {message.Kind} instead of {kind}.");
            }
        }

        private static T Deserialize<T>(JsonElement payload) =>
            payload.Deserialize<T>(ControlMessageSerializer.Options)
            ?? throw new InvalidDataException("The broker response payload is missing.");

        private sealed record BrokerHello(int ProcessId, bool Elevated);
    }
}
