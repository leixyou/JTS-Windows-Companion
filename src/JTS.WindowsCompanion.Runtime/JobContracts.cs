using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace JTS.WindowsCompanion.Runtime;

public enum DurableJobState { Queued, Running, Cancelling, Succeeded, Failed, Cancelled, Expired, Interrupted }

public sealed class JobRuntimeException(string code) : InvalidOperationException(code)
{
    public string Code { get; } = code;
}

/// <summary>The executor cannot attest that its processes have stopped. Never translate this to Cancelled.</summary>
public sealed class JobExecutionStateUnknownException() : InvalidOperationException("JOB_EXECUTOR_STATE_UNKNOWN");

public sealed record JobBinding(Guid RequestId, string Kind, string OwnerDeviceId, Guid GrantId,
    DateTimeOffset Deadline, bool AllowDisconnected, string PayloadSha256)
{
    internal void Validate(DateTimeOffset now, bool newSubmission)
    {
        if (RequestId == Guid.Empty || GrantId == Guid.Empty || !IsHash(OwnerDeviceId) || !IsHash(PayloadSha256)
            || Kind is not { Length: >= 1 and <= 64 } || !Kind.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_')
            || Deadline.Ticks % TimeSpan.TicksPerMillisecond != 0
            || (newSubmission && (Deadline <= now || Deadline > now.AddHours(24))))
            throw new JobRuntimeException("JOB_REQUEST_INVALID");
    }
    internal static bool IsHash(string value) => value is { Length: 64 } && value.All(c => c is >= 'a' and <= 'f' or >= '0' and <= '9');
    internal string RequestHash => Hash(JsonSerializer.SerializeToUtf8Bytes(new
    {
        requestId = RequestId.ToString("D"), kind = Kind, ownerDeviceId = OwnerDeviceId,
        grantId = GrantId.ToString("D"), deadlineUnixMilliseconds = Deadline.ToUnixTimeMilliseconds(),
        allowDisconnected = AllowDisconnected, payloadSha256 = PayloadSha256,
    }));
    internal byte[] ProtectionContext(string purpose) => Encoding.UTF8.GetBytes("JTS-DURABLE-JOB-V1\n" + purpose + "\n" + RequestHash);
    public static string Hash(ReadOnlySpan<byte> payload) => Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
}

// No record-generated payload logging. Callers retain their buffer; SubmitAsync takes a private copy.
public sealed class JobSubmission
{
    public JobBinding Binding { get; }
    public ReadOnlyMemory<byte> Payload { get; }
    public JobSubmission(Guid requestId, string kind, string ownerDeviceId, Guid grantId,
        DateTimeOffset deadline, ReadOnlyMemory<byte> payload, bool allowDisconnected = false)
    {
        Binding = new JobBinding(requestId, kind, ownerDeviceId, grantId,
            DateTimeOffset.FromUnixTimeMilliseconds(deadline.ToUnixTimeMilliseconds()), allowDisconnected, JobBinding.Hash(payload.Span));
        Payload = payload;
    }
    public override string ToString() => "JobSubmission (payload omitted)";
}

public sealed record JobSnapshot(JobBinding Binding, DurableJobState State, DateTimeOffset SubmittedAt,
    DateTimeOffset? StartedAt, DateTimeOffset? CompletedAt, string? ResultCode, int OutputBytes, bool DataExpired);

public sealed record DurableJobLimits
{
    public int MaximumQueuedJobs { get; init; } = 32;
    public int MaximumReceiptCount { get; init; } = 4096;
    public int MaximumConnectedOwners { get; init; } = 128;
    public int MaximumRememberedRevocations { get; init; } = 4096;
    public int MaximumPayloadBytes { get; init; } = 64 * 1024;
    public int MaximumOutputBytesPerJob { get; init; } = 128 * 1024;
    public long MaximumStoredOutputBytes { get; init; } = 8 * 1024 * 1024;
    public TimeSpan DataRetention { get; init; } = TimeSpan.FromDays(7);
    internal void Validate()
    {
        if (MaximumQueuedJobs is < 1 or > 128 || MaximumReceiptCount is < 1 or > 100_000
            || MaximumConnectedOwners is < 1 or > 1024 || MaximumRememberedRevocations is < 1 or > 100_000
            || MaximumPayloadBytes is < 1 or > 1024 * 1024 || MaximumOutputBytesPerJob is < 1 or > 1024 * 1024
            || MaximumStoredOutputBytes < MaximumOutputBytesPerJob || MaximumStoredOutputBytes > 256L * 1024 * 1024
            || DataRetention < TimeSpan.Zero || DataRetention > TimeSpan.FromDays(30))
            throw new ArgumentException("Invalid durable job bounds.");
    }
}

public interface ITaskPayloadProtector
{
    byte[] Protect(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> purpose);
    byte[] Unprotect(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> purpose);
}

public interface IJobGrantAuthority
{
    ValueTask<bool> CanExecuteAsync(JobBinding binding, CancellationToken cancellationToken);
}

public interface IJobOutputSink
{
    ValueTask AppendAsync(ReadOnlyMemory<byte> output, CancellationToken cancellationToken);
}

/// <summary>Executors must stop/drain actual child processes on cancellation, not just stop awaiting them.</summary>
public interface IJobExecutor
{
    ValueTask<JobExecutionResult> ExecuteAsync(JobBinding binding, ReadOnlyMemory<byte> payload,
        IJobOutputSink output, CancellationToken cancellationToken);
}

public sealed record JobExecutionResult(bool Success, string ResultCode);
