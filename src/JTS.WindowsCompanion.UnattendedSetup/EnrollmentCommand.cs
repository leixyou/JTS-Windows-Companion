using System.Text.Json;
using JTS.WindowsCompanion.Enrollment;
using JTS.WindowsCompanion.UnattendedInstallation;

namespace JTS.WindowsCompanion.UnattendedSetup;

internal static class EnrollmentCommand
{
    internal static async Task<int> RunAsync(SetupEntryMode mode, string bundleDirectory)
    {
        EnrollmentManagementStatus status;
        if (mode == SetupEntryMode.EnrollStandardInput)
        {
            using var inputTimeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
            var code = await EnrollmentCodeInput.ReadAsync(Console.In, inputTimeout.Token);
            status = await EnrollmentEntryWorkflow.EnrollAsync(code, WindowsInstallationPresence.Inspect(),
                async origin => { await WindowsUnattendedInstaller.InstallWithConsentAsync(bundleDirectory, origin); },
                WindowsEnrollmentManagementClient.EnrollAsync, CancellationToken.None);
        }
        else
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            status = await WindowsEnrollmentManagementClient.StatusAsync(deadline.Token);
        }
        // The authenticated service returns public identifiers only. Never include input code or exceptions.
        Console.Out.WriteLine(JsonSerializer.Serialize(new {
            state = status.State, deviceId = status.DeviceId, relayOrigin = status.RelayOrigin,
            invitationId = status.InvitationId, errorCode = SafeErrorCode(status.ErrorCode), rdpStatus = "notChecked"
        }));
        return status.State == "faulted" ? 1 : 0;
    }

    internal static string? SafeErrorCode(string? code) => code switch
    {
        null => null,
        "ENROLLMENT_ACCESS_DENIED" or "ENROLLMENT_SERVICE_UNAVAILABLE" or "ENROLLMENT_CODE_INVALID"
            or "ENROLLMENT_ORIGIN_MISMATCH" or "ENROLLMENT_ATTEMPT_ACTIVE" or "ENROLLMENT_INVITATION_CLOSED"
            or "ENROLLMENT_RELAY_UNAVAILABLE" or "ENROLLMENT_VERIFICATION_FAILED" => code,
        _ => "ENROLLMENT_FAILED"
    };
}
