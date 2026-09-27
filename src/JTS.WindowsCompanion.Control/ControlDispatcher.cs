using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.Control;

internal sealed class ControlDispatcher(CompanionControlHost host, DurableJobStore store, DurableJobRuntime runtime)
{
    internal async Task ServeAsync(Stream tls, string owner, CancellationToken token)
    {
        var window = Stopwatch.StartNew(); var count = 0;
        while (!token.IsCancellationRequested)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            deadline.CancelAfter(TimeSpan.FromSeconds(90)); // Idle or incomplete frame has the same bounded lifetime.
            var bytes = await ControlWire.ReadAsync(tls, deadline.Token).ConfigureAwait(false);
            if (bytes is null) return;
            byte[]? response = null;
            try
            {
                if (window.Elapsed >= TimeSpan.FromMinutes(1)) { window.Restart(); count = 0; }
                if (++count > 120) throw new ControlProtocolException("CONTROL_RATE_LIMIT");
                using var doc = ControlWire.Parse(bytes);
                var request = doc.RootElement;
                ControlWire.Fields(request, "version", "id", "operation", "grantId", "parameters");
                if (ControlWire.Integer(request, "version") != 1) throw new ControlProtocolException("CONTROL_VERSION_UNSUPPORTED");
                var id = ControlWire.Id(request, "id");
                var grant = ControlWire.Id(request, "grantId");
                var operation = ControlWire.Operation(ControlWire.Text(request, "operation", 32));
                deadline.CancelAfter(TimeSpan.FromSeconds(15));
                object? result = null; string? code = null;
                try
                {
                    result = await DispatchAsync(owner, grant, operation, request.GetProperty("parameters"), deadline.Token).ConfigureAwait(false);
                    // Authorization might have expired/revoked while the operation was awaiting I/O.
                    _ = await host.RequireGrantAsync(owner, grant, operation, deadline.Token).ConfigureAwait(false);
                }
                catch (ControlProtocolException error) { code = error.Code; }
                catch (JobRuntimeException error) { code = SafeJobCode(error.Code); }
                catch (OperationCanceledException) { throw; }
                catch { code = "CONTROL_OPERATION_FAILED"; }
                response = JsonSerializer.SerializeToUtf8Bytes(new { version = 1, id = id.ToString("D"), ok = code is null, result = code is null ? result : null, errorCode = code });
                await ControlWire.WriteAsync(tls, response, deadline.Token).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
                if (response is not null) CryptographicOperations.ZeroMemory(response);
            }
        }
    }

    private async Task<object> DispatchAsync(string owner, Guid grantId, ControlOperation op, JsonElement args, CancellationToken token)
    {
        var grant = await host.RequireGrantAsync(owner, grantId, op, token).ConfigureAwait(false);
        if (op == ControlOperation.Status)
        {
            ControlWire.Fields(args);
            return new { capabilities = grant.CapabilityNames, maximumPayloadBytes = ControlWire.MaximumPayloadBytes,
                maximumOutputChunkBytes = ControlWire.MaximumOutputChunkBytes };
        }
        if (op == ControlOperation.Submit)
        {
            ControlWire.Fields(args, "jobId", "kind", "deadlineUnixMilliseconds", "allowDisconnected", "payloadBase64");
            var kind = ControlWire.Text(args, "kind", 64);
            var id = ControlWire.Id(args, "jobId");
            var detached = ControlWire.Boolean(args, "allowDisconnected");
            DateTimeOffset deadline;
            try { deadline = DateTimeOffset.FromUnixTimeMilliseconds(ControlWire.Integer(args, "deadlineUnixMilliseconds")); }
            catch (ArgumentOutOfRangeException) { throw new ControlProtocolException("CONTROL_REQUEST_INVALID"); }
            var base64 = ControlWire.Text(args, "payloadBase64", 4 * ((ControlWire.MaximumPayloadBytes + 2) / 3));
            byte[] payload;
            try { payload = Convert.FromBase64String(base64); }
            catch (FormatException) { throw new ControlProtocolException("CONTROL_REQUEST_INVALID"); }
            try
            {
                if (payload.Length is 0 or > ControlWire.MaximumPayloadBytes || Convert.ToBase64String(payload) != base64)
                    throw new ControlProtocolException("CONTROL_REQUEST_INVALID");
                var submission = new JobSubmission(id, kind, owner, grantId, deadline, payload, detached);
                if (!grant.Allows(submission.Binding)) throw new ControlProtocolException("CONTROL_GRANT_REJECTED");
                var receipt = await runtime.SubmitAsync(submission, token).ConfigureAwait(false);
                host.Wake(); return Snapshot(receipt);
            }
            finally { CryptographicOperations.ZeroMemory(payload); }
        }
        if (op == ControlOperation.Output) ControlWire.Fields(args, "jobId", "offset", "maximumBytes");
        else ControlWire.Fields(args, "jobId");
        var jobId = ControlWire.Id(args, "jobId");
        if (op == ControlOperation.Cancel) return Snapshot(runtime.Cancel(jobId, owner, grantId));
        var job = store.Get(jobId, owner, grantId);
        if (op == ControlOperation.Get) return Snapshot(job);
        var offset = ControlWire.Integer(args, "offset"); var maximum = ControlWire.Integer(args, "maximumBytes");
        if (offset < 0 || offset > job.OutputBytes || maximum is < 1 or > ControlWire.MaximumOutputChunkBytes)
            throw new ControlProtocolException("CONTROL_OUTPUT_RANGE");
        var output = store.ReadOutput(jobId, owner, grantId);
        try
        {
            var length = Math.Min((int)maximum, output.Length - (int)offset);
            return new { jobId = jobId.ToString("D"), offset, nextOffset = offset + length, outputBytes = output.Length,
                dataBase64 = Convert.ToBase64String(output.AsSpan((int)offset, length)) };
        }
        finally { CryptographicOperations.ZeroMemory(output); }
    }

    private static object Snapshot(JobSnapshot snapshot) => new
    {
        jobId = snapshot.Binding.RequestId.ToString("D"), grantId = snapshot.Binding.GrantId.ToString("D"),
        kind = snapshot.Binding.Kind, deadlineUnixMilliseconds = snapshot.Binding.Deadline.ToUnixTimeMilliseconds(),
        allowDisconnected = snapshot.Binding.AllowDisconnected, state = snapshot.State.ToString().ToLowerInvariant(),
        submittedAtUnixMilliseconds = snapshot.SubmittedAt.ToUnixTimeMilliseconds(),
        startedAtUnixMilliseconds = snapshot.StartedAt?.ToUnixTimeMilliseconds(),
        completedAtUnixMilliseconds = snapshot.CompletedAt?.ToUnixTimeMilliseconds(), resultCode = snapshot.ResultCode,
        outputBytes = snapshot.OutputBytes, dataExpired = snapshot.DataExpired,
    };
    private static string SafeJobCode(string code) => code switch
    {
        "JOB_REQUEST_INVALID" or "JOB_IDEMPOTENCY_CONFLICT" or "JOB_PAYLOAD_INVALID" or "JOB_GRANT_REJECTED"
        or "JOB_OWNER_OFFLINE" or "JOB_RECEIPT_CAPACITY" or "JOB_QUEUE_FULL" or "JOB_NOT_FOUND"
        or "JOB_DATA_EXPIRED" => code,
        _ => "CONTROL_OPERATION_FAILED",
    };
}
