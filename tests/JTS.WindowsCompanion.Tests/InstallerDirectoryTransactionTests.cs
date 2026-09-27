using JTS.WindowsCompanion.Setup;

namespace JTS.WindowsCompanion.Tests;

public sealed class InstallerDirectoryTransactionTests
{
    [Fact]
    public void Commit_ReplacesTheWholeInstallationAndRetainsStateRoot()
    {
        using var layout = new TransactionTestLayout();
        using var lease = layout.AcquireLease();
        layout.CreateExistingInstallation();
        layout.CreateStagedInstallation();

        var transaction = InstallerDirectoryTransaction.Begin(
            layout.InstallRoot,
            layout.StagingRoot,
            layout.JournalPath,
            "registration-snapshot",
            lease);
        transaction.Activate();
        transaction.Commit();

        Assert.Equal("new-agent", layout.ReadInstalled("agent.exe"));
        Assert.False(File.Exists(Path.Combine(layout.InstallRoot, "old-only.txt")));
        Assert.Equal("paired-state", File.ReadAllText(layout.StateFile));
        Assert.True(File.Exists(layout.JournalPath));

        transaction.CompleteCommittedCleanup();

        Assert.False(File.Exists(layout.JournalPath));
        Assert.Empty(Directory.EnumerateDirectories(layout.Root, ".backup-*"));
    }

    [Fact]
    public void Rollback_RestoresEveryOldFileAndRegistrationMetadata()
    {
        using var layout = new TransactionTestLayout();
        using var lease = layout.AcquireLease();
        layout.CreateExistingInstallation();
        layout.CreateStagedInstallation();
        var transaction = InstallerDirectoryTransaction.Begin(
            layout.InstallRoot,
            layout.StagingRoot,
            layout.JournalPath,
            "exact-old-registration",
            lease);
        transaction.Activate();

        var recovery = transaction.RollbackFiles();

        Assert.True(recovery.RegistrationRestoreRequired);
        Assert.Equal("exact-old-registration", recovery.RecoveryMetadata);
        Assert.Equal("old-agent", layout.ReadInstalled("agent.exe"));
        Assert.Equal("old-only", layout.ReadInstalled("old-only.txt"));
        Assert.Equal("paired-state", File.ReadAllText(layout.StateFile));
        Assert.True(File.Exists(layout.JournalPath));

        transaction.CompleteRollback();
        Assert.False(File.Exists(layout.JournalPath));
    }

    [Fact]
    public void Rollback_FirstInstallRemovesTheActivatedDirectory()
    {
        using var layout = new TransactionTestLayout();
        using var lease = layout.AcquireLease();
        layout.CreateStagedInstallation();
        var transaction = InstallerDirectoryTransaction.Begin(
            layout.InstallRoot,
            layout.StagingRoot,
            layout.JournalPath,
            "no-old-registration",
            lease);
        transaction.Activate();

        _ = transaction.RollbackFiles();

        Assert.False(Directory.Exists(layout.InstallRoot));
        Assert.Equal("paired-state", File.ReadAllText(layout.StateFile));
        transaction.CompleteRollback();
    }

    [Fact]
    public void EmptyReplacement_CommitSupportsTransactionalUninstall()
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
        Assert.Empty(Directory.EnumerateFileSystemEntries(layout.InstallRoot));
        transaction.Commit();

        Assert.True(Directory.Exists(layout.InstallRoot));
        Assert.True(File.Exists(layout.JournalPath));

        transaction.CompleteCommittedCleanup();

        Assert.False(Directory.Exists(layout.InstallRoot));
        Assert.Equal("paired-state", File.ReadAllText(layout.StateFile));
    }

    [Fact]
    public void EmptyReplacement_RollbackRestoresUninstalledFiles()
    {
        using var layout = new TransactionTestLayout();
        using var lease = layout.AcquireLease();
        layout.CreateExistingInstallation();
        var transaction = InstallerDirectoryTransaction.Begin(
            layout.InstallRoot,
            layout.StagingRoot,
            layout.JournalPath,
            "old-registration",
            lease);
        transaction.Activate();

        _ = transaction.RollbackFiles();

        Assert.Equal("old-agent", layout.ReadInstalled("agent.exe"));
        Assert.Equal("old-only", layout.ReadInstalled("old-only.txt"));
        transaction.CompleteRollback();
    }

    [Fact]
    public void Recovery_RestoresAnOldDirectoryWhenCrashPrecedesPhaseWrite()
    {
        using var layout = new TransactionTestLayout();
        using var lease = layout.AcquireLease();
        layout.CreateExistingInstallation();
        layout.CreateStagedInstallation();
        _ = InstallerDirectoryTransaction.Begin(
            layout.InstallRoot,
            layout.StagingRoot,
            layout.JournalPath,
            "crash-registration",
            lease);
        var journal = InstallerTransactionJournalStore.Read(
            layout.JournalPath,
            layout.InstallRoot,
            lease);
        Directory.Move(layout.InstallRoot, journal.BackupRoot);

        var recovery = InstallerDirectoryTransaction.RecoverPending(
            layout.InstallRoot,
            layout.JournalPath,
            lease);

        Assert.True(recovery.RegistrationRestoreRequired);
        Assert.Equal("old-agent", layout.ReadInstalled("agent.exe"));
        Assert.False(Directory.Exists(layout.StagingRoot));
        InstallerDirectoryTransaction.CompletePendingRollback(
            layout.InstallRoot,
            layout.JournalPath,
            recovery.TransactionId,
            lease);
    }

    [Fact]
    public void Recovery_RollsBackWhenNewDirectoryMovedBeforePhaseWrite()
    {
        using var layout = new TransactionTestLayout();
        using var lease = layout.AcquireLease();
        layout.CreateExistingInstallation();
        layout.CreateStagedInstallation();
        _ = InstallerDirectoryTransaction.Begin(
            layout.InstallRoot,
            layout.StagingRoot,
            layout.JournalPath,
            "crash-registration",
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

        var recovery = InstallerDirectoryTransaction.RecoverPending(
            layout.InstallRoot,
            layout.JournalPath,
            lease);

        Assert.Equal("old-agent", layout.ReadInstalled("agent.exe"));
        Assert.Equal("old-only", layout.ReadInstalled("old-only.txt"));
        InstallerDirectoryTransaction.CompletePendingRollback(
            layout.InstallRoot,
            layout.JournalPath,
            recovery.TransactionId,
            lease);
    }

    [Fact]
    public void Recovery_CompletesCleanupWithoutRollingBackCommittedInstall()
    {
        using var layout = new TransactionTestLayout();
        using var lease = layout.AcquireLease();
        layout.CreateExistingInstallation();
        layout.CreateStagedInstallation();
        _ = InstallerDirectoryTransaction.Begin(
            layout.InstallRoot,
            layout.StagingRoot,
            layout.JournalPath,
            "unused-after-commit",
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
        Assert.Equal("new-agent", layout.ReadInstalled("agent.exe"));
        Assert.False(Directory.Exists(journal.BackupRoot));
        Assert.False(File.Exists(layout.JournalPath));
    }

    [Fact]
    public void Begin_RejectsAReparsePointStagingDirectory()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var layout = new TransactionTestLayout(createStagingDirectory: false);
        using var lease = layout.AcquireLease();
        var target = Path.Combine(layout.Root, "staging-target");
        Directory.CreateDirectory(target);
        Directory.CreateSymbolicLink(layout.StagingRoot, target);

        Assert.Throws<UnauthorizedAccessException>(
            () => InstallerDirectoryTransaction.Begin(
                layout.InstallRoot,
                layout.StagingRoot,
                layout.JournalPath,
                "registration-snapshot",
                lease));
    }
}
