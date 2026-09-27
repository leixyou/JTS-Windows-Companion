using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using JTS.WindowsCompanion.WorkerService;

namespace JTS.WindowsCompanion.UnattendedInstallation;

internal static class WindowsProvisioningLauncher
{
    private static readonly SemaphoreSlim LaunchGate = new(1);
    // An unknown stop must not unload DPAPI's profile or permit automatic account/state rollback.
    // Keep the native ownership alive until this installer exits; explicit recovery is a separate workflow.
    private static readonly List<object> UnconfirmedOwnership = [];

    internal static async Task RunAsync(LocalAccountIdentity authority, AccountPassword password,
        string verifiedProgramPath, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10) || !Environment.Is64BitProcess)
            throw new UnattendedInstallationException("PROVISION_WINDOWS_X64_REQUIRED");
        var command = ProvisioningLaunchPlan.CommandLine(authority, verifiedProgramPath);
        await LaunchGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { await RunWindowsAsync(authority, password, verifiedProgramPath, command, cancellationToken).ConfigureAwait(false); }
        finally { LaunchGate.Release(); }
    }

    [SupportedOSPlatform("windows")]
    private static async Task RunWindowsAsync(LocalAccountIdentity authority, AccountPassword password,
        string executable, string command, CancellationToken cancellationToken)
    {
        FileStream? program = null; SafeAccessTokenHandle? token = null, restricted = null;
        ProvisioningProfile? profile = null; ProvisioningDesktop? desktop = null; ProvisioningProcess? process = null;
        Exception? failure = null;
        var retain = false;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            new WindowsLocalAccountManager().VerifyOwned(authority);
            program = WindowsServiceProgramTrust.Open(executable, CompanionServiceProgram.AuthorityProvisioner);
            ProvisioningPrivileges.Run(() => true); // Refuse SYSTEM, impersonated and non-elevated callers before logon.
            ProvisioningNative.Require(ProvisioningNative.LogonUser(authority.Name, ".", password.Pointer, 5, 0, out token),
                "PROVISION_SERVICE_LOGON_FAILED");
            GC.KeepAlive(password);
            restricted = ProvisioningToken.Restricted(token, authority.Sid);
            profile = new ProvisioningProfile(token); profile.Load(authority.Name);
            var environment = ProvisioningLaunchPlan.EnvironmentBlock(Environment.SystemDirectory,
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), profile.Directory(),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), authority.Name, Environment.MachineName);
            desktop = new ProvisioningDesktop(authority.Sid);
            cancellationToken.ThrowIfCancellationRequested();
            process = new ProvisioningProcess();
            process.Start(restricted, authority.Sid, executable, command, environment, desktop.Name);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(ProvisioningLaunchPlan.ExecutionLimit);
            await process.WaitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        { failure = new UnattendedInstallationException(cancellationToken.IsCancellationRequested ? "PROVISION_CANCELLED" : "PROVISION_TIMED_OUT"); }
        catch (UnattendedInstallationException error) { failure = error; }
        catch (Exception) { failure = new UnattendedInstallationException("PROVISION_LAUNCH_FAILED"); }

        try { if (process is not null) await process.DrainAsync().ConfigureAwait(false); }
        catch (Exception) { retain = true; failure = new UnattendedInstallationException("PROVISION_PROCESS_STOP_UNCONFIRMED"); }
        process?.Dispose(); // Kill-on-close remains a final safeguard, not evidence that stopping succeeded.
        if (!retain)
        {
            try { profile?.UnloadAfterConfirmedStop(); }
            catch (Exception) { retain = true; failure = new UnattendedInstallationException("PROVISION_PROFILE_UNLOAD_UNCONFIRMED"); }
        }
        if (retain)
        {
            lock (UnconfirmedOwnership)
                UnconfirmedOwnership.Add(new object?[] { token, restricted, profile, desktop, program });
        }
        else { desktop?.Dispose(); restricted?.Dispose(); token?.Dispose(); program?.Dispose(); }
        if (failure is not null) throw failure;
    }
}
