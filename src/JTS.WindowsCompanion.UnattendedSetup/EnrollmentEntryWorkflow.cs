using JTS.WindowsCompanion.Enrollment;
using JTS.WindowsCompanion.UnattendedInstallation;

namespace JTS.WindowsCompanion.UnattendedSetup;

/// <summary>The same fresh/installed entry sequence for the GUI and stdin CLI.</summary>
internal static class EnrollmentEntryWorkflow
{
    internal static async Task<EnrollmentManagementStatus> EnrollAsync(string code, CompanionInstallationPresence presence,
        Func<string, Task> install, Func<string, CancellationToken, Task<EnrollmentManagementStatus>> enroll, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var origin = EnrollmentCodeInspector.GetRelayOrigin(code);
        switch (presence)
        {
            case CompanionInstallationPresence.Absent:
                // The installation transaction owns its completion. Closing the UI cannot cancel it midway.
                await install(origin.AbsoluteUri);
                break;
            case CompanionInstallationPresence.Installed:
                break;
            default:
                throw new InvalidOperationException("INSTALL_EXISTING_STATE_REQUIRES_LOCAL_REVIEW");
        }
        token.ThrowIfCancellationRequested();
        return await enroll(code, token);
    }
}
