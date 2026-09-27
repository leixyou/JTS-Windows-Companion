using JTS.WindowsCompanion.Setup;

namespace JTS.WindowsCompanion.Tests;

public sealed class InstallerCrashRecoveryTests
{
    [Fact]
    public void Recovery_RemovesFirstInstallMovedBeforePhaseWrite()
    {
        using var layout = new TransactionTestLayout();
        using var lease = layout.AcquireLease();
        layout.CreateStagedInstallation();
        _ = InstallerDirectoryTransaction.Begin(
            layout.InstallRoot,
            layout.StagingRoot,
            layout.JournalPath,
            "empty-registration",
            lease);
        Directory.Move(layout.StagingRoot, layout.InstallRoot);

        var recovery = InstallerDirectoryTransaction.RecoverPending(
            layout.InstallRoot,
            layout.JournalPath,
            lease);

        Assert.True(recovery.RegistrationRestoreRequired);
        Assert.False(Directory.Exists(layout.InstallRoot));
        Assert.Equal("paired-state", File.ReadAllText(layout.StateFile));
    }

    [Fact]
    public void Recovery_ResumesAfterOldDirectoryWasRestored()
    {
        using var layout = new TransactionTestLayout();
        using var lease = layout.AcquireLease();
        layout.CreateExistingInstallation();
        layout.CreateStagedInstallation();
        var transaction = InstallerDirectoryTransaction.Begin(
            layout.InstallRoot,
            layout.StagingRoot,
            layout.JournalPath,
            "old-registration",
            lease);
        transaction.Activate();
        var journal = InstallerTransactionJournalStore.Read(
            layout.JournalPath,
            layout.InstallRoot,
            lease);
        journal = InstallerTransactionJournalStore.AdvancePhase(
            layout.JournalPath,
            layout.InstallRoot,
            journal.TransactionId,
            InstallerTransactionPhase.NewInstallationActivated,
            InstallerTransactionPhase.RollbackStarted,
            lease);
        InstallerLayout.DeleteDirectoryWithoutFollowingLinks(layout.InstallRoot);
        Directory.Move(journal.BackupRoot, layout.InstallRoot);

        var recovery = InstallerDirectoryTransaction.RecoverPending(
            layout.InstallRoot,
            layout.JournalPath,
            lease);

        Assert.Equal("old-registration", recovery.RecoveryMetadata);
        Assert.Equal("old-agent", layout.ReadInstalled("agent.exe"));
        var recoveredJournal = InstallerTransactionJournalStore.Read(
            layout.JournalPath,
            layout.InstallRoot,
            lease);
        Assert.Equal(InstallerTransactionPhase.FilesRolledBack, recoveredJournal.Phase);
    }

    [Fact]
    public void Recovery_DoesNotDeleteAConcurrentFirstInstallation()
    {
        using var layout = new TransactionTestLayout();
        using var lease = layout.AcquireLease();
        layout.CreateStagedInstallation();
        _ = InstallerDirectoryTransaction.Begin(
            layout.InstallRoot,
            layout.StagingRoot,
            layout.JournalPath,
            "empty-registration",
            lease);
        Directory.CreateDirectory(layout.InstallRoot);
        File.WriteAllText(Path.Combine(layout.InstallRoot, "unrelated.exe"), "retain");

        Assert.Throws<InvalidDataException>(
            () => InstallerDirectoryTransaction.RecoverPending(
                layout.InstallRoot,
                layout.JournalPath,
                lease));
        Assert.True(File.Exists(Path.Combine(layout.InstallRoot, "unrelated.exe")));
        Assert.True(Directory.Exists(layout.StagingRoot));
    }

    [Fact]
    public void Recovery_DoesNotDiscardBackupWhenCommittedLiveDirectoryIsMissing()
    {
        using var layout = new TransactionTestLayout();
        using var lease = layout.AcquireLease();
        layout.CreateExistingInstallation();
        layout.CreateStagedInstallation();
        _ = InstallerDirectoryTransaction.Begin(
            layout.InstallRoot,
            layout.StagingRoot,
            layout.JournalPath,
            "old-registration",
            lease);
        var journal = InstallerTransactionJournalStore.Read(
            layout.JournalPath,
            layout.InstallRoot,
            lease);
        Directory.Move(layout.InstallRoot, journal.BackupRoot);
        journal = InstallerTransactionJournalStore.AdvancePhase(
            layout.JournalPath,
            layout.InstallRoot,
            journal.TransactionId,
            InstallerTransactionPhase.Prepared,
            InstallerTransactionPhase.OldInstallationMoved,
            lease);
        Directory.Move(layout.StagingRoot, layout.InstallRoot);
        journal = InstallerTransactionJournalStore.AdvancePhase(
            layout.JournalPath,
            layout.InstallRoot,
            journal.TransactionId,
            InstallerTransactionPhase.OldInstallationMoved,
            InstallerTransactionPhase.NewInstallationActivated,
            lease);
        InstallerLayout.DeleteDirectoryWithoutFollowingLinks(layout.InstallRoot);
        journal = InstallerTransactionJournalStore.AdvancePhase(
            layout.JournalPath,
            layout.InstallRoot,
            journal.TransactionId,
            InstallerTransactionPhase.NewInstallationActivated,
            InstallerTransactionPhase.Committed,
            lease);

        Assert.Throws<InvalidDataException>(
            () => InstallerDirectoryTransaction.RecoverPending(
                layout.InstallRoot,
                layout.JournalPath,
                lease));
        Assert.True(Directory.Exists(journal.BackupRoot));
        Assert.Equal("old-agent", File.ReadAllText(Path.Combine(journal.BackupRoot, "agent.exe")));
    }

    [Fact]
    public void Recovery_CompletesCommittedTransactionalUninstall()
    {
        using var layout = new TransactionTestLayout();
        using var lease = layout.AcquireLease();
        layout.CreateExistingInstallation();
        var transaction = InstallerDirectoryTransaction.Begin(
            layout.InstallRoot,
            layout.StagingRoot,
            layout.JournalPath,
            "old-registration",
            lease,
            deleteActivatedDirectoryOnCommit: true);
        transaction.Activate();
        var journal = InstallerTransactionJournalStore.Read(
            layout.JournalPath,
            layout.InstallRoot,
            lease);
        journal = InstallerTransactionJournalStore.AdvancePhase(
            layout.JournalPath,
            layout.InstallRoot,
            journal.TransactionId,
            InstallerTransactionPhase.NewInstallationActivated,
            InstallerTransactionPhase.Committed,
            lease);

        var recovery = InstallerDirectoryTransaction.RecoverPending(
            layout.InstallRoot,
            layout.JournalPath,
            lease);

        Assert.False(recovery.RegistrationRestoreRequired);
        Assert.False(Directory.Exists(layout.InstallRoot));
        Assert.False(Directory.Exists(journal.BackupRoot));
        Assert.False(File.Exists(layout.JournalPath));
        Assert.Equal("paired-state", File.ReadAllText(layout.StateFile));
    }
}
