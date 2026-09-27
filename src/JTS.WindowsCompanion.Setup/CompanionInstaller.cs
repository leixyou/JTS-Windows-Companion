using System.Reflection;
using System.Runtime.InteropServices;
using JTS.WindowsCompanion.Lifecycle;
using JTS.WindowsCompanion.Security;
using JTS.WindowsCompanion.Windows.Security;

namespace JTS.WindowsCompanion.Setup;

internal sealed class CompanionInstaller
{
    private readonly InstallerLayout _layout;
    private readonly InstallerOperationLease _operationLease;
    private readonly CompanionProcessController _processes;
    private readonly CurrentUserRegistrationManager _registration;
    private readonly CompanionRollbackCoordinator _rollback;
    private readonly string _setupExecutable = Environment.ProcessPath
        ?? throw new InvalidOperationException("The setup executable path is unavailable.");

    public CompanionInstaller(
        InstallerLayout layout,
        InstallerOperationLease operationLease)
    {
        _layout = layout;
        _operationLease = operationLease;
        _operationLease.DemandProtects(_layout.TransactionJournalPath);
        _processes = new CompanionProcessController(_layout);
        _registration = new CurrentUserRegistrationManager(_layout, _processes);
        _rollback = new CompanionRollbackCoordinator(_layout, _processes);
    }

    public bool RequiresDetachedInstall =>
        string.Equals(
            Path.GetDirectoryName(Path.GetFullPath(_setupExecutable)),
            Path.GetFullPath(_layout.InstallRoot),
            StringComparison.OrdinalIgnoreCase);

    public async Task<CompanionAgentLaunch?> InstallAsync(
        bool launchAgent,
        CancellationToken cancellationToken,
        CompanionDelegatedEnrollmentRequest? enrollment = null,
        string? enrollmentSha256 = null)
    {
        EnsureSupportedPlatform();
        InstallerLayout.EnsureSafeInstallRoot(_layout.LocalApplicationData, _layout.InstallRoot);
        using var pairedPeers = new DpapiCompanionPeerStore(Path.Combine(_layout.StateRoot, "paired-peer.v1.json"));
        if (enrollment is not null)
        {
            InstallerLayout.EnsureSafeInstallRoot(_layout.LocalApplicationData, _layout.StateRoot);
            var proposedGrant = await WindowsDelegatedEnrollment.PrepareAsync(
                _layout.StateRoot, enrollment, enrollmentSha256!, cancellationToken).ConfigureAwait(false);
            await pairedPeers.ValidateEnrollmentAsync(proposedGrant, cancellationToken).ConfigureAwait(false);
        }
        PrepareForTransaction();

        string? stagingRoot = null;
        InstallerDirectoryTransaction? transaction = null;
        CurrentUserRegistrationSnapshot? registrationSnapshot = null;
        CompanionAgentLaunch? agentLaunch = null;
        var previousAgentWasRunning = false;
        try
        {
            stagingRoot = _layout.CreateStagingRoot();
            var stagedAgent = Path.Combine(stagingRoot, InstallerLayout.AgentFileName);
            var stagedBroker = Path.Combine(stagingRoot, InstallerLayout.BrokerFileName);
            var stagedSetup = Path.Combine(stagingRoot, InstallerLayout.SetupFileName);
            var stagedManifest = Path.Combine(stagingRoot, ReleaseManifestTrust.ManifestFileName);
            var assembly = Assembly.GetExecutingAssembly();
            var release = ReadEmbeddedReleaseManifest(assembly);
            await InstallerLayout.ExtractResourceAsync(
                assembly,
                InstallerLayout.ReleaseManifestResourceName,
                stagedManifest,
                cancellationToken).ConfigureAwait(false);
            await InstallerLayout.ExtractResourceAsync(
                assembly,
                InstallerLayout.AgentResourceName,
                stagedAgent,
                cancellationToken).ConfigureAwait(false);
            await InstallerLayout.ExtractResourceAsync(
                assembly,
                InstallerLayout.BrokerResourceName,
                stagedBroker,
                cancellationToken).ConfigureAwait(false);
            using (LockedExecutableCopy.Create(_setupExecutable, stagedSetup))
            {
                release.VerifyFile(stagedAgent, InstallerLayout.AgentFileName);
                release.VerifyFile(stagedBroker, InstallerLayout.BrokerFileName);
            }

            registrationSnapshot = CurrentUserRegistrationSnapshot.Capture();
            using var preparedStop = _processes.PrepareStopInstalledProcesses();
            previousAgentWasRunning = preparedStop.State.AgentWasRunning;
            var recoveryMetadata = CompanionSetupRecoveryMetadata.Create(
                CompanionSetupOperation.Install,
                registrationSnapshot.Serialize(),
                previousAgentWasRunning,
                launchAgentAfterCommit: launchAgent && enrollment is null,
                purgeStateAfterCommit: false);
            transaction = InstallerDirectoryTransaction.Begin(
                _layout.InstallRoot,
                stagingRoot,
                _layout.TransactionJournalPath,
                recoveryMetadata.Serialize(),
                _operationLease);

            preparedStop.Execute();
            transaction.Activate();

            VerifyInstalledRelease(release);

            _registration.Write();
            transaction.Commit();
            if (enrollment is not null)
            {
                // The committed recovery record intentionally has no auto-launch:
                // interrupted enrollment must never be mistaken for completed consent.
                var grant = await WindowsDelegatedEnrollment.PrepareAsync(
                    _layout.StateRoot, enrollment, enrollmentSha256!, cancellationToken).ConfigureAwait(false);
                _ = await pairedPeers.EnrollDelegatedAsync(grant, cancellationToken).ConfigureAwait(false);
            }
            if (launchAgent)
            {
                var readiness = new CompanionAgentReadinessServer();
                try
                {
                    agentLaunch = new CompanionAgentLaunch(
                        _processes.StartAgent(readiness.PipeName),
                        readiness);
                }
                catch
                {
                    readiness.Dispose();
                    throw;
                }
            }
            transaction.CompleteCommittedCleanup();
            return agentLaunch;
        }
        catch (Exception installException)
        {
            agentLaunch?.Dispose();
            if (transaction is null || transaction.IsCommitted || registrationSnapshot is null)
            {
                throw;
            }

            var rollbackFailures = _rollback.TryRestore(
                transaction,
                registrationSnapshot,
                restartPreviousAgent: previousAgentWasRunning);
            if (rollbackFailures.Count > 0)
            {
                throw new AggregateException(
                    "Setup failed and could not completely restore the previous installation. Run Setup again to resume recovery.",
                    new[] { installException }.Concat(rollbackFailures));
            }
            throw;
        }
        finally
        {
            if (transaction is null && stagingRoot is not null)
            {
                TryDeleteUnownedStaging(stagingRoot);
            }
        }
    }

    public System.Diagnostics.Process LaunchDetachedInstaller(bool quiet, string? enrollmentPath = null, string? enrollmentSha256 = null)
    {
        EnsureSupportedPlatform();
        return CreateTemporarySetupLauncher().Launch("--install-internal", quiet,
            enrollmentPath: enrollmentPath, enrollmentSha256: enrollmentSha256);
    }

    public void LaunchDetachedUninstaller(bool quiet, bool purgeData)
    {
        EnsureSupportedPlatform();
        CreateTemporarySetupLauncher().Launch("--uninstall-internal", quiet, purgeData).Dispose();
    }

    public async Task RevokeDelegationAsync(Guid grantId, CancellationToken cancellationToken)
    {
        EnsureSupportedPlatform();
        InstallerLayout.EnsureSafeInstallRoot(_layout.LocalApplicationData, _layout.StateRoot);
        using var peers = new DpapiCompanionPeerStore(Path.Combine(_layout.StateRoot, "paired-peer.v1.json"));
        // Validate before touching the running session. The second check under the
        // store's cross-process lease makes revoke-vs-enrollment races fail closed.
        await peers.ValidateRevocationAsync(grantId, cancellationToken).ConfigureAwait(false);
        using var preparedStop = _processes.PrepareStopInstalledProcesses();
        preparedStop.Execute();
        await peers.RevokeDelegatedAsync(grantId, cancellationToken).ConfigureAwait(false);
    }

    public void UninstallInternal(bool purgeData)
    {
        EnsureSupportedPlatform();
        InstallerLayout.EnsureSafeInstallRoot(_layout.LocalApplicationData, _layout.InstallRoot);
        PrepareForTransaction();

        string? stagingRoot = null;
        InstallerDirectoryTransaction? transaction = null;
        CurrentUserRegistrationSnapshot? registrationSnapshot = null;
        var previousAgentWasRunning = false;
        try
        {
            stagingRoot = _layout.CreateStagingRoot();
            registrationSnapshot = CurrentUserRegistrationSnapshot.Capture();
            using var preparedStop = _processes.PrepareStopInstalledProcesses();
            previousAgentWasRunning = preparedStop.State.AgentWasRunning;
            var recoveryMetadata = CompanionSetupRecoveryMetadata.Create(
                CompanionSetupOperation.Uninstall,
                registrationSnapshot.Serialize(),
                previousAgentWasRunning,
                launchAgentAfterCommit: false,
                purgeStateAfterCommit: purgeData);
            transaction = InstallerDirectoryTransaction.Begin(
                _layout.InstallRoot,
                stagingRoot,
                _layout.TransactionJournalPath,
                recoveryMetadata.Serialize(),
                _operationLease,
                deleteActivatedDirectoryOnCommit: true);
            preparedStop.Execute();
            transaction.Activate();

            CurrentUserRegistrationManager.Remove();
            transaction.Commit();
            if (purgeData)
            {
                InstallerLayout.EnsureSafeInstallRoot(_layout.LocalApplicationData, _layout.StateRoot);
                InstallerLayout.DeleteDirectoryWithoutFollowingLinks(_layout.StateRoot);
            }
            transaction.CompleteCommittedCleanup();
        }
        catch (Exception uninstallException)
        {
            if (transaction is null || transaction.IsCommitted || registrationSnapshot is null)
            {
                throw;
            }
            var rollbackFailures = _rollback.TryRestore(
                transaction,
                registrationSnapshot,
                restartPreviousAgent: previousAgentWasRunning);
            if (rollbackFailures.Count > 0)
            {
                throw new AggregateException(
                    "Uninstall failed and could not completely restore the previous installation. Run Setup again to resume recovery.",
                    new[] { uninstallException }.Concat(rollbackFailures));
            }
            throw;
        }
        finally
        {
            if (transaction is null && stagingRoot is not null)
            {
                TryDeleteUnownedStaging(stagingRoot);
            }
        }
    }

    private static VerifiedReleaseManifest ReadEmbeddedReleaseManifest(Assembly assembly)
    {
        using var resource = assembly.GetManifestResourceStream(InstallerLayout.ReleaseManifestResourceName)
            ?? throw new UnauthorizedAccessException("The authenticated Companion release manifest is missing.");
        if (resource.Length is <= 0 or > 64 * 1024)
        {
            throw new UnauthorizedAccessException("The embedded Companion release manifest size is invalid.");
        }
        var envelope = new byte[(int)resource.Length];
        resource.ReadExactly(envelope);
        return ReleaseManifestTrust.VerifyUsingEmbeddedKey(envelope);
    }

    private void VerifyInstalledRelease(VerifiedReleaseManifest expectedRelease)
    {
        var installedRelease = ReleaseManifestTrust.LoadForExecutable(_layout.AgentPath);
        if (!string.Equals(installedRelease.PayloadSha256, expectedRelease.PayloadSha256, StringComparison.Ordinal))
        {
            throw new UnauthorizedAccessException("The installed Companion release manifest changed during setup.");
        }
        expectedRelease.VerifyFile(_layout.BrokerPath, InstallerLayout.BrokerFileName);
    }

    private void RecoverPendingTransaction()
    {
        if (!InstallerDirectoryTransaction.HasPending(
                _layout.TransactionJournalPath,
                _operationLease))
        {
            return;
        }

        var pending = InstallerDirectoryTransaction.ReadPendingState(
            _layout.InstallRoot,
            _layout.TransactionJournalPath,
            _operationLease);
        var metadata = CompanionSetupRecoveryMetadata.Deserialize(pending.RecoveryMetadata);
        if (pending.IsCommitted)
        {
            PurgeCommittedStateIfRequested(metadata);
            FulfillCommittedAgentLaunchIfRequested(metadata);
            _ = InstallerDirectoryTransaction.RecoverPending(
                _layout.InstallRoot,
                _layout.TransactionJournalPath,
                _operationLease,
                pending.TransactionId);
            return;
        }

        using var preparedStop = _processes.PrepareStopInstalledProcesses();
        preparedStop.Execute();
        var recovery = InstallerDirectoryTransaction.RecoverPending(
            _layout.InstallRoot,
            _layout.TransactionJournalPath,
            _operationLease,
            pending.TransactionId);
        if (recovery.RegistrationRestoreRequired)
        {
            CurrentUserRegistrationSnapshot.Deserialize(metadata.RegistrationSnapshot).Restore();
            if (metadata.PreviousAgentWasRunning && File.Exists(_layout.AgentPath))
            {
                _processes.StartAgent();
            }
            InstallerDirectoryTransaction.CompletePendingRollback(
                _layout.InstallRoot,
                _layout.TransactionJournalPath,
                recovery.TransactionId,
                _operationLease);
        }
    }

    private void PrepareForTransaction()
    {
        RecoverPendingTransaction();
        InstallerResidueScavenger.CleanupBeforeTransaction(
            _layout.InstallParent,
            _layout.TransactionJournalPath,
            _operationLease);
    }

    private void FulfillCommittedAgentLaunchIfRequested(
        CompanionSetupRecoveryMetadata metadata)
    {
        if (!metadata.LaunchAgentAfterCommit)
        {
            return;
        }

        using var preparedStop = _processes.PrepareStopInstalledProcesses();
        preparedStop.Execute();
        _ = _processes.StartAgent();
    }

    private void PurgeCommittedStateIfRequested(CompanionSetupRecoveryMetadata metadata)
    {
        if (!metadata.PurgeStateAfterCommit)
        {
            return;
        }

        InstallerLayout.EnsureSafeInstallRoot(_layout.LocalApplicationData, _layout.StateRoot);
        InstallerLayout.DeleteDirectoryWithoutFollowingLinks(_layout.StateRoot);
    }

    private TemporarySetupLauncher CreateTemporarySetupLauncher() =>
        new(_setupExecutable);

    private static void TryDeleteUnownedStaging(string stagingRoot)
    {
        try
        {
            InstallerLayout.DeleteDirectoryWithoutFollowingLinks(stagingRoot);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // No live files reference a pre-transaction staging directory. A later setup can remove it.
        }
    }

    private static void EnsureSupportedPlatform()
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10) || RuntimeInformation.ProcessArchitecture != Architecture.X64)
        {
            throw new PlatformNotSupportedException("JTS Windows Companion requires Windows 10 or Windows 11 x64.");
        }
    }
}
