using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Transfers;

namespace JTS.WindowsCompanion.Worker;

public enum VrcFactoryWorkerAction
{
    Doctor,
    Submit,
    Status,
    Cancel,
    Collect,
}

/// <summary>
/// Bridges the Companion DVC to the already-installed VRC Factory worker CLI.
/// The executable, executable digest, subcommands, arguments, timeouts, and IO
/// limits are installation policy. None of them are accepted from a task.
/// </summary>
public sealed class VrcFactoryWorkerBridge
{
    public const int MaximumJsonOutputBytes = 512 * 1024;
    public const int MaximumErrorBytes = 64 * 1024;
    public const string ProviderId = "vrc-factory";
    public const string WorkerProtocol = "fixed-dvc-v1";
    public const string SubmitTransferPurpose = "vrc-worker-submit";
    public const string ResultTransferPurpose = "vrc-worker-result";

    private static readonly IReadOnlySet<string> RequiredDoctorChecks = new HashSet<string>(
        ["platform", "python", "unity", "vpm", "worker", "spool", "consumer"],
        StringComparer.Ordinal);
    private static readonly IReadOnlySet<string> WorkerStates = new HashSet<string>(
        ["queued", "running", "cancel-requested", "cancelled", "succeeded", "failed", "unknown"],
        StringComparer.Ordinal);

    private readonly string _executablePath;
    private readonly string _expectedExecutableSha256;
    private readonly IFixedWorkerProcessRunner _processRunner;
    private readonly IInstalledExecutableVerifier _executableVerifier;
    private readonly BinaryTransferCoordinator _transfers;
    private readonly IVrcEnvelopeSecurity _envelopeSecurity;

    public VrcFactoryWorkerBridge(
        string executablePath,
        string expectedExecutableSha256,
        BinaryTransferCoordinator transfers,
        IVrcEnvelopeSecurity envelopeSecurity,
        IFixedWorkerProcessRunner? processRunner = null,
        IInstalledExecutableVerifier? executableVerifier = null)
    {
        _executablePath = ValidateExecutablePath(executablePath);
        _expectedExecutableSha256 = NormalizeSha256(expectedExecutableSha256, nameof(expectedExecutableSha256));
        _transfers = transfers ?? throw new ArgumentNullException(nameof(transfers));
        _envelopeSecurity = envelopeSecurity ?? throw new ArgumentNullException(nameof(envelopeSecurity));
        _processRunner = processRunner ?? new FixedWorkerProcessRunner();
        _executableVerifier = executableVerifier ?? new InstalledExecutableVerifier();
    }

    public async ValueTask<object?> ExecuteAsync(
        VrcFactoryWorkerAction action,
        JsonElement parameters,
        CancellationToken cancellationToken)
    {
        await _executableVerifier.VerifyAsync(
            _executablePath,
            _expectedExecutableSha256,
            cancellationToken).ConfigureAwait(false);

        return action switch
        {
            VrcFactoryWorkerAction.Doctor => await DoctorAsync(parameters, cancellationToken).ConfigureAwait(false),
            VrcFactoryWorkerAction.Submit => await SubmitAsync(parameters, cancellationToken).ConfigureAwait(false),
            VrcFactoryWorkerAction.Status => await JobOperationAsync("status", parameters, cancellationToken).ConfigureAwait(false),
            VrcFactoryWorkerAction.Cancel => await JobOperationAsync("cancel", parameters, cancellationToken).ConfigureAwait(false),
            VrcFactoryWorkerAction.Collect => await CollectAsync(parameters, cancellationToken).ConfigureAwait(false),
            _ => throw new CompanionProtocolException("WORKER_ACTION_INVALID", "The worker action is not installed."),
        };
    }

    private async ValueTask<object> DoctorAsync(JsonElement parameters, CancellationToken cancellationToken)
    {
        RequireProperties(parameters);
        var completed = await RunAsync(
            ["doctor"],
            ReadOnlyMemory<byte>.Empty,
            TimeSpan.FromSeconds(30),
            MaximumJsonOutputBytes,
            cancellationToken).ConfigureAwait(false);
        var report = ParseJsonObject(completed.StandardOutput, "WORKER_DOCTOR_INVALID");
        var checks = ReadDoctorChecks(report);
        var checkNames = checks
            .Select(check => check.GetProperty("name").GetString()!)
            .ToHashSet(StringComparer.Ordinal);
        var errors = new List<string>();
        foreach (var required in RequiredDoctorChecks.Order(StringComparer.Ordinal))
        {
            var check = checks.FirstOrDefault(candidate =>
                candidate.GetProperty("name").GetString() == required);
            if (check.ValueKind == JsonValueKind.Undefined)
            {
                errors.Add($"{required}: required check is missing");
            }
            else if (!check.TryGetProperty("ok", out var ok) || ok.ValueKind != JsonValueKind.True)
            {
                errors.Add($"{required}: check failed");
            }
        }

        var ready = completed.ExitCode is 0 or 2
            && errors.Count == 0
            && RequiredDoctorChecks.IsSubsetOf(checkNames);
        return new
        {
            schemaVersion = "2.0",
            ok = ready,
            workerProtocol = WorkerProtocol,
            companion = new { available = true, compatible = true },
            worker = new
            {
                ready,
                provider = ProviderId,
                protocol = WorkerProtocol,
                executableSha256 = _expectedExecutableSha256,
            },
            checks,
            errors,
            networkRequirements = new
            {
                localLanRdp = true,
                tailscale = false,
                ssh = false,
            },
        };
    }

    private async ValueTask<object> SubmitAsync(JsonElement parameters, CancellationToken cancellationToken)
    {
        RequireProperties(parameters, "jobId", "transferId", "totalBytes", "bundleSha256", "jobEnvelope");
        var jobId = ReadJobId(parameters);
        var transferId = ReadTransferId(parameters);
        var totalBytes = ReadPositiveInt64(parameters, "totalBytes");
        var bundleSha256 = NormalizeSha256(
            ReadRequiredString(parameters, "bundleSha256", "WORKER_BUNDLE_INVALID"),
            "bundleSha256");
        var jobEnvelope = await _envelopeSecurity.VerifyJobAsync(
            parameters.GetProperty("jobEnvelope"),
            jobId,
            totalBytes,
            bundleSha256,
            cancellationToken).ConfigureAwait(false);
        var upload = await _transfers.GetValidatedUploadAsync(
            transferId,
            SubmitTransferPurpose,
            totalBytes,
            bundleSha256,
            cancellationToken).ConfigureAwait(false);
        try
        {
            var completed = await RunAsync(
                ["submit-stdin"],
                ReadOnlyMemory<byte>.Empty,
                TimeSpan.FromMinutes(10),
                MaximumJsonOutputBytes,
                cancellationToken,
                standardInputFilePath: upload.FilePath).ConfigureAwait(false);
            var response = RequireSuccessfulJson(completed, "WORKER_SUBMIT_FAILED");
            ValidateJobResponse(response, jobId);
            var reportedSha256 = ReadRequiredString(response, "bundleSha256", "WORKER_RESPONSE_INVALID");
            if (!CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(bundleSha256),
                    Convert.FromHexString(NormalizeSha256(reportedSha256, "bundleSha256"))))
            {
                throw new CompanionProtocolException(
                    "WORKER_BUNDLE_HASH_MISMATCH",
                    "The VRC worker did not bind the submitted bundle to its SHA-256 digest.");
            }

            return AddEnvelope(response, "jobEnvelope", jobEnvelope);
        }
        finally
        {
            await _transfers.ReleaseAsync(transferId, CancellationToken.None).ConfigureAwait(false);
        }
    }

    private async ValueTask<object> JobOperationAsync(
        string command,
        JsonElement parameters,
        CancellationToken cancellationToken)
    {
        RequireProperties(parameters, "jobId");
        var jobId = ReadJobId(parameters);
        var completed = await RunAsync(
            [command, "--job-id", jobId],
            ReadOnlyMemory<byte>.Empty,
            TimeSpan.FromSeconds(30),
            MaximumJsonOutputBytes,
            cancellationToken).ConfigureAwait(false);
        var response = RequireSuccessfulJson(completed, "WORKER_OPERATION_FAILED");
        ValidateJobResponse(response, jobId);
        return response;
    }

    private async ValueTask<object> CollectAsync(JsonElement parameters, CancellationToken cancellationToken)
    {
        RequireProperties(parameters, "jobId");
        var jobId = ReadJobId(parameters);
        var reservation = await _transfers.ReserveDownloadAsync(
            ResultTransferPurpose,
            cancellationToken).ConfigureAwait(false);
        try
        {
            var completed = await RunAsync(
                ["collect-stdout", "--job-id", jobId],
                ReadOnlyMemory<byte>.Empty,
                TimeSpan.FromMinutes(10),
                checked((int)BinaryTransferCoordinator.MaximumTransferBytes),
                cancellationToken,
                standardOutputFilePath: reservation.FilePath).ConfigureAwait(false);
            if (completed.ExitCode != 0)
            {
                throw new CompanionProtocolException(
                    "WORKER_COLLECT_FAILED",
                    "The VRC worker did not return a verified result bundle.");
            }

            var transfer = await _transfers.FinalizeDownloadAsync(
                reservation.TransferId,
                cancellationToken).ConfigureAwait(false);
            var resultEnvelope = await _envelopeSecurity.SignResultAsync(
                jobId,
                "collected",
                transfer.TotalBytes,
                transfer.Sha256,
                cancellationToken).ConfigureAwait(false);
            return new
            {
                ok = true,
                jobId,
                state = "collected",
                transferId = transfer.TransferId,
                totalBytes = transfer.TotalBytes,
                bundleSha256 = transfer.Sha256,
                resultEnvelope,
            };
        }
        catch
        {
            await _transfers.ReleaseAsync(reservation.TransferId, CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    private async ValueTask<FixedWorkerProcessResult> RunAsync(
        IReadOnlyList<string> arguments,
        ReadOnlyMemory<byte> standardInput,
        TimeSpan timeout,
        int maximumStandardOutputBytes,
        CancellationToken cancellationToken,
        string? standardInputFilePath = null,
        string? standardOutputFilePath = null)
    {
        try
        {
            return await _processRunner.RunAsync(
                new FixedWorkerProcessRequest(
                    _executablePath,
                    arguments,
                    standardInput,
                    timeout,
                    maximumStandardOutputBytes,
                    MaximumErrorBytes,
                    standardInputFilePath,
                    standardOutputFilePath),
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new CompanionProtocolException("WORKER_TIMEOUT", "The fixed VRC worker operation timed out.");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (CompanionProtocolException)
        {
            throw;
        }
        catch (Exception)
        {
            throw new CompanionProtocolException("WORKER_UNAVAILABLE", "The installed VRC worker could not be started.");
        }
    }

    private static JsonElement RequireSuccessfulJson(FixedWorkerProcessResult completed, string errorCode)
    {
        var response = ParseJsonObject(completed.StandardOutput, "WORKER_RESPONSE_INVALID");
        if (completed.ExitCode != 0
            || !response.TryGetProperty("ok", out var ok)
            || ok.ValueKind != JsonValueKind.True)
        {
            throw new CompanionProtocolException(errorCode, "The fixed VRC worker operation failed.");
        }

        return response;
    }

    private static IReadOnlyDictionary<string, object?> AddEnvelope(
        JsonElement response,
        string propertyName,
        object envelope)
    {
        var result = response.EnumerateObject().ToDictionary(
            property => property.Name,
            property => (object?)property.Value.Clone(),
            StringComparer.Ordinal);
        result[propertyName] = envelope;
        return result;
    }

    private static void ValidateJobResponse(JsonElement response, string expectedJobId)
    {
        if (ReadRequiredString(response, "jobId", "WORKER_RESPONSE_INVALID") != expectedJobId)
        {
            throw new CompanionProtocolException(
                "WORKER_JOB_MISMATCH",
                "The VRC worker response belongs to a different job.");
        }

        var state = ReadRequiredString(response, "state", "WORKER_RESPONSE_INVALID");
        if (!WorkerStates.Contains(state))
        {
            throw new CompanionProtocolException("WORKER_STATE_INVALID", "The VRC worker returned an unknown state.");
        }
    }

    private static IReadOnlyList<JsonElement> ReadDoctorChecks(JsonElement report)
    {
        if (!report.TryGetProperty("checks", out var checks)
            || checks.ValueKind != JsonValueKind.Array)
        {
            throw new CompanionProtocolException("WORKER_DOCTOR_INVALID", "The VRC worker doctor returned no checks.");
        }

        var result = new List<JsonElement>();
        foreach (var check in checks.EnumerateArray())
        {
            if (check.ValueKind != JsonValueKind.Object
                || !check.TryGetProperty("name", out var name)
                || name.ValueKind != JsonValueKind.String)
            {
                throw new CompanionProtocolException("WORKER_DOCTOR_INVALID", "A VRC worker doctor check is invalid.");
            }

            if (name.GetString() == "tailscale")
            {
                continue;
            }

            result.Add(check.Clone());
        }

        return result;
    }

    private static JsonElement ParseJsonObject(ReadOnlyMemory<byte> bytes, string errorCode)
    {
        try
        {
            using var document = JsonDocument.Parse(bytes);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new CompanionProtocolException(errorCode, "The VRC worker response is not an object.");
            }

            return document.RootElement.Clone();
        }
        catch (JsonException)
        {
            throw new CompanionProtocolException(errorCode, "The VRC worker returned invalid JSON.");
        }
    }

    private static string ReadJobId(JsonElement parameters)
    {
        var value = ReadRequiredString(parameters, "jobId", "WORKER_JOB_ID_INVALID");
        if (value.Length is < 2 or > 96
            || !char.IsAsciiLetterOrDigit(value[0])
            || value[0] is >= 'A' and <= 'Z'
            || value.Any(character =>
                !(char.IsAsciiDigit(character)
                  || character is >= 'a' and <= 'z'
                  || character is '_' or '-')))
        {
            throw new CompanionProtocolException("WORKER_JOB_ID_INVALID", "The VRC worker job ID is invalid.");
        }

        return value;
    }

    private static string ReadRequiredString(JsonElement value, string property, string errorCode)
    {
        if (value.ValueKind != JsonValueKind.Object
            || !value.TryGetProperty(property, out var element)
            || element.ValueKind != JsonValueKind.String
            || string.IsNullOrEmpty(element.GetString()))
        {
            throw new CompanionProtocolException(errorCode, $"The VRC worker {property} field is invalid.");
        }

        return element.GetString()!;
    }

    private static void RequireProperties(JsonElement parameters, params string[] allowed)
    {
        if (parameters.ValueKind != JsonValueKind.Object)
        {
            throw new CompanionProtocolException("WORKER_REQUEST_INVALID", "Worker parameters must be an object.");
        }

        var expected = allowed.ToHashSet(StringComparer.Ordinal);
        var actual = parameters.EnumerateObject().Select(property => property.Name).ToArray();
        if (actual.Any(property => !expected.Contains(property))
            || expected.Any(property => !actual.Contains(property, StringComparer.Ordinal)))
        {
            throw new CompanionProtocolException(
                "WORKER_REQUEST_INVALID",
                "The worker request contains missing or unsupported fields.");
        }
    }

    private static Guid ReadTransferId(JsonElement parameters)
    {
        var value = ReadRequiredString(parameters, "transferId", "WORKER_TRANSFER_INVALID");
        return Guid.TryParse(value, out var transferId) && transferId != Guid.Empty
            ? transferId
            : throw new CompanionProtocolException("WORKER_TRANSFER_INVALID", "The worker transfer ID is invalid.");
    }

    private static long ReadPositiveInt64(JsonElement parameters, string name)
    {
        if (!parameters.TryGetProperty(name, out var value)
            || !value.TryGetInt64(out var result)
            || result <= 0)
        {
            throw new CompanionProtocolException("WORKER_TRANSFER_INVALID", "The worker transfer size is invalid.");
        }

        return result;
    }

    private static string ValidateExecutablePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value)
            || !Path.IsPathFullyQualified(value)
            || value.StartsWith("\\\\", StringComparison.Ordinal)
            || value.StartsWith("//", StringComparison.Ordinal)
            || !Path.GetExtension(value).Equals(".exe", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "The VRC worker must be a fixed, local, fully-qualified .exe path.",
                nameof(value));
        }

        return Path.GetFullPath(value);
    }

    private static string NormalizeSha256(string value, string parameterName)
    {
        if (value.Length != 64 || value.Any(character => !char.IsAsciiHexDigit(character)))
        {
            throw new ArgumentException("A lowercase or uppercase SHA-256 digest is required.", parameterName);
        }

        return value.ToLowerInvariant();
    }

}
