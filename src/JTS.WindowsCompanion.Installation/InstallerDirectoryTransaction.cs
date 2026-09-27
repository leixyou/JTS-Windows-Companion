namespace JTS.WindowsCompanion.Setup;

internal sealed record InstallerRecoveryResult(
    string TransactionId,
    bool RegistrationRestoreRequired,
    string RecoveryMetadata)
{
    public static InstallerRecoveryResult None { get; } = new(string.Empty, false, string.Empty);
}

internal sealed record InstallerPendingTransactionState(
    string TransactionId,
    InstallerTransactionPhase Phase,
    string RecoveryMetadata)
{
    public bool IsCommitted => Phase == InstallerTransactionPhase.Committed;
}

internal sealed class InstallerDirectoryTransaction
{
    private readonly string _journalPath;
    private readonly InstallerOperationLease _lease;
    private InstallerTransactionJournal _journal;
    private bool _completed;

    private InstallerDirectoryTransaction(
        string journalPath,
        InstallerTransactionJournal journal,
        InstallerOperationLease lease)
    {
        _journalPath = Path.GetFullPath(journalPath);
        _journal = journal;
        _lease = lease;
    }

    public bool IsCommitted => _journal.Phase == InstallerTransactionPhase.Committed;

    public static bool HasPending(
        string journalPath,
        InstallerOperationLease lease)
    {
        lease.DemandProtects(journalPath);
        return File.Exists(journalPath) || Directory.Exists(journalPath);
    }

    public static InstallerPendingTransactionState ReadPendingState(
        string expectedInstallRoot,
        string journalPath,
        InstallerOperationLease lease)
    {
        var journal = InstallerTransactionJournalStore.Read(
            journalPath,
            expectedInstallRoot,
            lease);
        return new InstallerPendingTransactionState(
            journal.TransactionId,
            journal.Phase,
            journal.RecoveryMetadata);
    }

    public static InstallerDirectoryTransaction Begin(
        string installRoot,
        string stagingRoot,
        string journalPath,
        string recoveryMetadata,
        InstallerOperationLease lease,
        bool deleteActivatedDirectoryOnCommit = false)
    {
        lease.DemandProtects(journalPath);
        if (Directory.Exists(journalPath))
        {
            throw new InvalidOperationException("A previous setup transaction must be recovered first.");
        }
        RejectDirectoryReparsePoint(stagingRoot);
        if (!Directory.Exists(stagingRoot))
        {
            throw new DirectoryNotFoundException("The setup staging directory is missing.");
        }
        if (File.Exists(installRoot) && !Directory.Exists(installRoot))
        {
            throw new UnauthorizedAccessException("The installation path is occupied by a file.");
        }

        var journal = InstallerTransactionJournalStore.Create(
            installRoot,
            stagingRoot,
            deleteActivatedDirectoryOnCommit,
            recoveryMetadata);
        try
        {
            InstallerTransactionJournalStore.CreateNew(
                journalPath,
                installRoot,
                journal,
                lease);
        }
        catch (IOException) when (File.Exists(journalPath) || Directory.Exists(journalPath))
        {
            throw new InvalidOperationException(
                "A previous setup transaction must be recovered first.");
        }
        return new InstallerDirectoryTransaction(journalPath, journal, lease);
    }

    public void Activate()
    {
        EnsureActive(InstallerTransactionPhase.Prepared);
        if (_journal.HadExistingInstallation)
        {
            RejectDirectoryReparsePoint(_journal.InstallRoot);
            if (!Directory.Exists(_journal.InstallRoot))
            {
                throw new DirectoryNotFoundException("The existing installation disappeared during setup.");
            }
            if (Directory.Exists(_journal.BackupRoot) || File.Exists(_journal.BackupRoot))
            {
                throw new IOException("The setup backup directory already exists.");
            }

            Directory.Move(_journal.InstallRoot, _journal.BackupRoot);
            UpdatePhase(InstallerTransactionPhase.OldInstallationMoved);
        }
        else if (Directory.Exists(_journal.InstallRoot) || File.Exists(_journal.InstallRoot))
        {
            throw new IOException("An installation appeared while setup was preparing the transaction.");
        }

        RejectDirectoryReparsePoint(_journal.StagingRoot);
        Directory.Move(_journal.StagingRoot, _journal.InstallRoot);
        UpdatePhase(InstallerTransactionPhase.NewInstallationActivated);
    }

    public InstallerRecoveryResult RollbackFiles()
    {
        if (_completed || IsCommitted)
        {
            throw new InvalidOperationException("A committed setup transaction cannot be rolled back.");
        }

        var result = RecoverPending(
            _journal.InstallRoot,
            _journalPath,
            _lease,
            _journal.TransactionId);
        _journal = InstallerTransactionJournalStore.Read(
            _journalPath,
            _journal.InstallRoot,
            _lease);
        return result;
    }

    public void CompleteRollback()
    {
        if (_completed || IsCommitted)
        {
            throw new InvalidOperationException("The setup transaction is not awaiting rollback completion.");
        }
        CompletePendingRollback(
            _journal.InstallRoot,
            _journalPath,
            _journal.TransactionId,
            _lease);
        _completed = true;
    }

    public void Commit()
    {
        EnsureActive(InstallerTransactionPhase.NewInstallationActivated);
        UpdatePhase(InstallerTransactionPhase.Committed);
        _completed = true;
    }

    public void CompleteCommittedCleanup()
    {
        if (!IsCommitted)
        {
            throw new InvalidOperationException("The setup transaction has not committed.");
        }
        _ = InstallerTransactionRecovery.RecoverPending(
            _journal.InstallRoot,
            _journalPath,
            _lease,
            _journal.TransactionId);
        if (File.Exists(_journalPath))
        {
            throw new IOException("The committed setup transaction still has pending cleanup.");
        }
    }

    public static InstallerRecoveryResult RecoverPending(
        string expectedInstallRoot,
        string journalPath,
        InstallerOperationLease lease,
        string? expectedTransactionId = null) =>
        InstallerTransactionRecovery.RecoverPending(
            expectedInstallRoot,
            journalPath,
            lease,
            expectedTransactionId);

    public static void CompletePendingRollback(
        string expectedInstallRoot,
        string journalPath,
        string transactionId,
        InstallerOperationLease lease) =>
        InstallerTransactionRecovery.CompletePendingRollback(
            expectedInstallRoot,
            journalPath,
            transactionId,
            lease);

    private void UpdatePhase(InstallerTransactionPhase phase)
    {
        _journal = InstallerTransactionJournalStore.AdvancePhase(
            _journalPath,
            _journal.InstallRoot,
            _journal.TransactionId,
            _journal.Phase,
            phase,
            _lease);
    }

    private void EnsureActive(InstallerTransactionPhase expectedPhase)
    {
        if (_completed || _journal.Phase != expectedPhase)
        {
            throw new InvalidOperationException("The setup transaction is in an invalid state.");
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

}
