using System.Runtime.Versioning;
using System.Text.Json;

namespace JTS.WindowsCompanion.Enrollment;

[SupportedOSPlatform("windows")]
public static class WindowsEnrollmentManagementClient
{
    public static Task<EnrollmentManagementStatus> StatusAsync(CancellationToken token = default) => SendAsync(new(1, "status", null, null), token);
    public static Task<EnrollmentManagementStatus> EnrollAsync(string code, CancellationToken token = default) => SendAsync(new(1, "enroll", code, null), token);
    public static Task<EnrollmentManagementStatus> RevokeAsync(Guid invitationId, CancellationToken token = default) => SendAsync(new(1, "revoke", null, invitationId), token);
    private static async Task<EnrollmentManagementStatus> SendAsync(EnrollmentManagementRequest request, CancellationToken token)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(TimeSpan.FromSeconds(30));
        try
        {
            using var pipe = await WindowsEnrollmentNative.ConnectAsync(timeout.Token).ConfigureAwait(false);
            await EnrollmentManagementWire.WriteAsync(pipe, request, timeout.Token).ConfigureAwait(false);
            var bytes = await EnrollmentManagementWire.ReceiveReplyAsync(pipe, timeout.Token).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(bytes); var p = doc.RootElement;
            EnrollmentCrypto.Fields(p, "state", "deviceId", "relayOrigin", "invitationId", "errorCode");
            var status = JsonSerializer.Deserialize<EnrollmentManagementStatus>(bytes, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                ?? throw new EnrollmentException("ENROLLMENT_RESPONSE_INVALID");
            if (status.State == "error") throw new EnrollmentException(status.ErrorCode ?? "ENROLLMENT_REQUEST_FAILED");
            return status;
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested) { throw new EnrollmentException("ENROLLMENT_SERVICE_UNAVAILABLE"); }
    }
}

[SupportedOSPlatform("windows")]
public sealed class WindowsEnrollmentManagementServer(string authoritySid, EnrollmentCoordinator coordinator)
{
    public async Task RunAsync(CancellationToken token)
    {
        // One held first-instance pipe prevents another local process from taking this name between requests.
        using var pipe = WindowsEnrollmentNative.CreateServer(authoritySid);
        while (true)
        {
            await pipe.WaitForConnectionAsync(token).ConfigureAwait(false);
            using var requestTime = CancellationTokenSource.CreateLinkedTokenSource(token); requestTime.CancelAfter(TimeSpan.FromSeconds(30));
            try
            {
                // Windows impersonates the security context of the last message read, not merely the connected process.
                // Read a bounded frame first; no parsing or operation is permitted before token verification.
                var frame = await EnrollmentManagementWire.ReadAsync(pipe, requestTime.Token).ConfigureAwait(false);
                WindowsEnrollmentNative.VerifyClient(pipe);
                var request = EnrollmentManagementWire.Parse(frame);
                var status = request.Operation switch
                {
                    "status" => await coordinator.StatusAsync(requestTime.Token).ConfigureAwait(false),
                    "enroll" => await coordinator.EnrollAsync(request.Code!, requestTime.Token).ConfigureAwait(false),
                    "revoke" => await coordinator.RevokeAsync(request.InvitationId!.Value, requestTime.Token).ConfigureAwait(false),
                    _ => throw new EnrollmentException("ENROLLMENT_REQUEST_INVALID"),
                };
                await EnrollmentManagementWire.ReplyAsync(pipe, status, requestTime.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or OperationCanceledException or System.Security.SecurityException)
            {
                try { await EnrollmentManagementWire.ReplyAsync(pipe, new EnrollmentManagementStatus("error", "", "", null,
                    error is EnrollmentException known ? known.Code : "ENROLLMENT_REQUEST_FAILED"), requestTime.Token).ConfigureAwait(false); }
                catch (Exception failure) when (failure is IOException or OperationCanceledException) { }
            }
            finally { if (pipe.IsConnected) pipe.Disconnect(); }
        }
    }
}
