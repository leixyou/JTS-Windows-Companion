namespace JTS.WindowsCompanion.Setup;

internal static class InstallerTransactionRecovery
{
    public static InstallerRecoveryResult RecoverPending(
        string expectedInstallRoot,
        string journalPath,
        InstallerOperationLease lease,
        string? expectedTransactionId = null)
    {
        if (!File.Exists(journalPath))
        {
            if (expectedTransactionId is not null)
            {
                throw new InvalidOperationException("The setup transaction journal disappeared unexpectedly.");
            }
            return InstallerRecoveryResult.None;
        }

        var journal = InstallerTransactionJournalStore.Read(
            journalPath,
            expectedInstallRoot,
            lease);
        DemandExpectedTransaction(journal, expectedTransactionId);
        if (journal.Phase == InstallerTransactionPhase.Committed)
        {
            CleanupCommitted(journal, journalPath, lease);
            return new InstallerRecoveryResult(journal.TransactionId, false, string.Empty);
        }
        if (journal.Phase == InstallerTransactionPhase.FilesRolledBack)
        {
            ValidateRolledBackState(journal);
            return new InstallerRecoveryResult(
                journal.TransactionId,
                true,
                journal.RecoveryMetadata);
        }

        ValidatePreRollbackState(journal);
        if (journal.Phase != InstallerTransactionPhase.RollbackStarted)
        {
            journal = InstallerTransactionJournalStore.AdvancePhase(
                journalPath,
                expectedInstallRoot,
                journal.TransactionId,
                journal.Phase,
                InstallerTransactionPhase.RollbackStarted,
                lease);
        }

        RestorePreviousDirectoryState(journal);
        journal = InstallerTransactionJournalStore.AdvancePhase(
            journalPath,
            expectedInstallRoot,
            journal.TransactionId,
            InstallerTransactionPhase.RollbackStarted,
            InstallerTransactionPhase.FilesRolledBack,
            lease);
        return new InstallerRecoveryResult(
            journal.TransactionId,
            true,
            journal.RecoveryMetadata);
    }

    public static void CompletePendingRollback(
        string expectedInstallRoot,
        string journalPath,
        string transactionId,
        InstallerOperationLease lease)
    {
        var journal = InstallerTransactionJournalStore.Read(
            journalPath,
            expectedInstallRoot,
            lease);
        DemandExpectedTransaction(journal, transactionId);
        if (journal.Phase != InstallerTransactionPhase.FilesRolledBack)
        {
            throw new InvalidOperationException("Setup cannot complete a rollback before its files are restored.");
        }
        ValidateRolledBackState(journal);
        InstallerTransactionJournalStore.DeleteExpected(
            journalPath,
            expectedInstallRoot,
            transactionId,
            InstallerTransactionPhase.FilesRolledBack,
            lease);
    }

    private static void ValidatePreRollbackState(InstallerTransactionJournal journal)
    {
        RejectDirectoryFile(journal.InstallRoot);
        RejectDirectoryFile(journal.StagingRoot);
        RejectDirectoryFile(journal.BackupRoot);
        RejectDirectoryReparsePoint(journal.InstallRoot);
        RejectDirectoryReparsePoint(journal.StagingRoot);
        RejectDirectoryReparsePoint(journal.BackupRoot);

        var liveExists = Directory.Exists(journal.InstallRoot);
        var stagingExists = Directory.Exists(journal.StagingRoot);
        var backupExists = Directory.Exists(journal.BackupRoot);
        if (journal.HadExistingInstallation)
        {
            var valid = journal.Phase switch
            {
                InstallerTransactionPhase.Prepared =>
                    liveExists && stagingExists && !backupExists ||
                    !liveExists && stagingExists && backupExists,
                InstallerTransactionPhase.OldInstallationMoved =>
                    backupExists && (liveExists ^ stagingExists),
                InstallerTransactionPhase.NewInstallationActivated =>
                    liveExists && !stagingExists && backupExists,
                InstallerTransactionPhase.RollbackStarted =>
                    backupExists || liveExists,
                _ => false,
            };
            if (!valid)
            {
                throw new InvalidDataException("The previous installation no longer has a recoverable directory state.");
            }
        }
        else
        {
            var valid = !backupExists && journal.Phase switch
            {
                InstallerTransactionPhase.Prepared => liveExists ^ stagingExists,
                InstallerTransactionPhase.NewInstallationActivated => liveExists && !stagingExists,
                InstallerTransactionPhase.RollbackStarted => true,
                _ => false,
            };
            if (!valid)
            {
                throw new InvalidDataException("The first-time installation no longer has a recoverable directory state.");
            }
        }
    }

    private static void RestorePreviousDirectoryState(InstallerTransactionJournal journal)
    {
        if (journal.HadExistingInstallation)
        {
            if (Directory.Exists(journal.BackupRoot))
            {
                DeleteDirectoryIfPresent(journal.InstallRoot);
                RejectDirectoryReparsePoint(journal.BackupRoot);
                Directory.Move(journal.BackupRoot, journal.InstallRoot);
            }
            else if (!Directory.Exists(journal.InstallRoot))
            {
                throw new InvalidDataException("The previous installation cannot be restored.");
            }
        }
        else
        {
            DeleteDirectoryIfPresent(journal.InstallRoot);
        }

        DeleteDirectoryIfPresent(journal.StagingRoot);
    }

    private static void ValidateRolledBackState(InstallerTransactionJournal journal)
    {
        RejectDirectoryFile(journal.InstallRoot);
        RejectDirectoryFile(journal.BackupRoot);
        RejectDirectoryFile(journal.StagingRoot);
        if (journal.HadExistingInstallation != Directory.Exists(journal.InstallRoot) ||
            Directory.Exists(journal.BackupRoot) ||
            Directory.Exists(journal.StagingRoot))
        {
            throw new InvalidDataException("The setup rollback directory state is incomplete.");
        }
    }

    private static void CleanupCommitted(
        InstallerTransactionJournal journal,
        string journalPath,
        InstallerOperationLease lease)
    {
        if (journal.DeleteActivatedDirectoryOnCommit)
        {
            DeleteDirectoryIfPresent(journal.InstallRoot);
        }
        else
        {
            RejectDirectoryFile(journal.InstallRoot);
            RejectDirectoryReparsePoint(journal.InstallRoot);
            if (!Directory.Exists(journal.InstallRoot))
            {
                throw new InvalidDataException("The committed installation directory is missing.");
            }
        }
        DeleteDirectoryIfPresent(journal.BackupRoot);
        DeleteDirectoryIfPresent(journal.StagingRoot);
        if ((!journal.DeleteActivatedDirectoryOnCommit || !Directory.Exists(journal.InstallRoot)) &&
            !Directory.Exists(journal.BackupRoot) &&
            !Directory.Exists(journal.StagingRoot))
        {
            InstallerTransactionJournalStore.DeleteExpected(
                journalPath,
                journal.InstallRoot,
                journal.TransactionId,
                InstallerTransactionPhase.Committed,
                lease);
        }
    }

    private static void DemandExpectedTransaction(
        InstallerTransactionJournal journal,
        string? expectedTransactionId)
    {
        if (expectedTransactionId is not null &&
            !string.Equals(journal.TransactionId, expectedTransactionId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("The setup transaction journal changed unexpectedly.");
        }
    }

    private static void DeleteDirectoryIfPresent(string path)
    {
        RejectDirectoryFile(path);
        if (Directory.Exists(path))
        {
            InstallerLayout.DeleteDirectoryWithoutFollowingLinks(path);
        }
    }

    private static void RejectDirectoryReparsePoint(string path)
    {
        if (Directory.Exists(path) &&
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new UnauthorizedAccessException("Setup does not move a symbolic link or reparse-point directory.");
        }
    }

    private static void RejectDirectoryFile(string path)
    {
        if (File.Exists(path) && !Directory.Exists(path))
        {
            throw new UnauthorizedAccessException("A setup transaction directory is occupied by a file.");
        }
    }
}
