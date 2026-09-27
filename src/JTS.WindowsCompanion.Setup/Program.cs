using JTS.WindowsCompanion.Security;
using JTS.WindowsCompanion.Windows.Security;

namespace JTS.WindowsCompanion.Setup;

internal static class Program
{
    private static readonly TimeSpan AgentReadinessTimeout = TimeSpan.FromSeconds(15);

    [STAThread]
    private static int Main(string[] arguments)
    {
        InstallerOptions options;
        try
        {
            options = InstallerOptions.Parse(arguments);
        }
        catch (Exception exception) when (exception is ArgumentException)
        {
            SetupUserInterface.ShowError("The setup command line is invalid.");
            return 2;
        }

        TemporarySetupCleanupScheduler.TryScheduleForCurrentProcess(
            Environment.ProcessPath ?? string.Empty);

        var purgeData = options.PurgeData;
        if (options.Action == InstallerAction.Uninstall && !options.Quiet)
        {
            if (!SetupUserInterface.Confirm("Remove JTS Windows Companion from this Windows account?"))
            {
                return 0;
            }
            if (!purgeData)
            {
                purgeData = SetupUserInterface.Confirm(
                    "Also remove the paired Mac identity, transfer cache, and Companion settings? Choose No to preserve them for reinstall.");
            }
        }

        InstallerLayout layout;
        InstallerOperationLease? operationLease;
        try
        {
            layout = new InstallerLayout();
            operationLease = InstallerOperationLease.TryAcquire(
                layout.OperationLockPath,
                options.Action is InstallerAction.InstallInternal or InstallerAction.UninstallInternal
                    ? TimeSpan.FromSeconds(30)
                    : TimeSpan.Zero);
        }
        catch (Exception exception) when (
            exception is IOException or
            UnauthorizedAccessException or
            InvalidDataException)
        {
            if (!options.Quiet)
            {
                SetupUserInterface.ShowError(
                    "Setup could not establish its cross-session operation lock.\n\n" +
                    exception.Message);
            }
            return 1;
        }
        if (operationLease is null)
        {
            if (!options.Quiet)
            {
                SetupUserInterface.ShowError("Another JTS Windows Companion setup operation is already running.");
            }
            return 3;
        }

        string? successMessage = null;
        Exception? setupFailure = null;
        CompanionAgentLaunch? agentLaunch = null;
        var delegatedInstallerStarted = false;
        using (operationLease)
        {
            try
            {
                var enrollment = options.DelegatedEnrollmentPath is { } enrollmentPath
                    ? WindowsDelegatedEnrollment.ReadRequest(enrollmentPath, options.DelegatedEnrollmentSha256!, DateTimeOffset.UtcNow)
                    : null;
                var installer = new CompanionInstaller(layout, operationLease);
                switch (options.Action)
                {
                    case InstallerAction.Install:
                    case InstallerAction.Repair:
                        if (installer.RequiresDetachedInstall)
                        {
                            var child = installer.LaunchDetachedInstaller(options.Quiet,
                                options.DelegatedEnrollmentPath, options.DelegatedEnrollmentSha256);
                            child.Dispose();
                            delegatedInstallerStarted = enrollment is not null;
                            break;
                        }
                        goto case InstallerAction.InstallInternal;
                    case InstallerAction.InstallInternal:
                        agentLaunch = installer.InstallAsync(
                                launchAgent: true,
                                CancellationToken.None, enrollment, options.DelegatedEnrollmentSha256)
                            .GetAwaiter()
                            .GetResult();
                        if (agentLaunch is null)
                        {
                            throw new InvalidOperationException(
                                "The installed Companion Agent launch was not prepared.");
                        }
                        break;
                    case InstallerAction.RevokeDelegation:
                        installer.RevokeDelegationAsync(options.RevokeDelegationGrantId!.Value, CancellationToken.None)
                            .GetAwaiter().GetResult();
                        successMessage = "The specified delegation was revoked and the Companion session was stopped.";
                        break;
                    case InstallerAction.Uninstall:
                        installer.LaunchDetachedUninstaller(options.Quiet, purgeData);
                        break;
                    case InstallerAction.UninstallInternal:
                        installer.UninstallInternal(options.PurgeData);
                        successMessage = "JTS Windows Companion was removed from this Windows account.";
                        break;
                    default:
                        throw new InvalidOperationException("The setup action is unsupported.");
                }
            }
            catch (Exception exception)
            {
                setupFailure = exception;
            }
        }

        // An installed Setup must exit so its image can be replaced. A delegated
        // self-repair reports deferred status, not a completed enrollment. Calling
        // the distribution Setup from outside the install root remains synchronous.
        if (setupFailure is null && delegatedInstallerStarted) return 4;

        if (setupFailure is null && agentLaunch is not null)
        {
            try
            {
                agentLaunch.WaitForReadyAsync(
                        AgentReadinessTimeout,
                        CancellationToken.None)
                    .GetAwaiter()
                    .GetResult();
                successMessage =
                    "JTS Windows Companion 2.0 is installed and its RDP channel is ready for this Windows user.";
            }
            catch (Exception exception)
            {
                setupFailure = new InvalidOperationException(
                    "The installation was committed, but the Companion Agent did not become ready " +
                    "in the active RDP session. Start an RDP session and run Repair.",
                    exception);
            }
            finally
            {
                agentLaunch.Dispose();
            }
        }

        if (setupFailure is not null)
        {
            if (!options.Quiet)
            {
                SetupUserInterface.ShowError(
                    "Setup could not complete. No credentials, commands, or file contents were logged.\n\n" +
                    setupFailure.Message);
            }
            return 1;
        }
        if (!options.Quiet && successMessage is not null)
        {
            SetupUserInterface.ShowSuccess(successMessage);
        }
        return 0;
    }
}
