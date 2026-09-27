using System.Text.Json;

namespace JTS.WindowsCompanion.Setup;

internal enum InstallerTransactionPhase
{
    Prepared,
    OldInstallationMoved,
    NewInstallationActivated,
    RollbackStarted,
    FilesRolledBack,
    Committed,
}

internal sealed record InstallerTransactionJournal(
    int SchemaVersion,
    string TransactionId,
    InstallerTransactionPhase Phase,
    string InstallRoot,
    string StagingRoot,
    string BackupRoot,
    bool HadExistingInstallation,
    bool DeleteActivatedDirectoryOnCommit,
    string RecoveryMetadata);

internal static class InstallerTransactionJournalStore
{
    private const int CurrentSchemaVersion = 2;
    private const int MaximumJournalBytes = 1024 * 1024;
    private const int MaximumRecoveryMetadataCharacters = 400 * 1024;
    private const string StagingPrefix = ".setup-";
    private const string BackupPrefix = ".backup-";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = false,
        WriteIndented = false,
    };

    public static InstallerTransactionJournal Create(
        string installRoot,
        string stagingRoot,
        bool deleteActivatedDirectoryOnCommit,
        string recoveryMetadata)
    {
        var normalizedStagingRoot = Path.GetFullPath(stagingRoot);
        var stagingName = Path.GetFileName(normalizedStagingRoot);
        if (!stagingName.StartsWith(StagingPrefix, StringComparison.Ordinal) ||
            !Guid.TryParseExact(stagingName[StagingPrefix.Length..], "N", out _))
        {
            throw new InvalidDataException("The setup staging directory name is invalid.");
        }

        var transactionId = stagingName[StagingPrefix.Length..];
        var installParent = Directory.GetParent(Path.GetFullPath(installRoot))?.FullName
            ?? throw new InvalidDataException("The installation directory has no parent.");
        var journal = new InstallerTransactionJournal(
            CurrentSchemaVersion,
            transactionId,
            InstallerTransactionPhase.Prepared,
            Path.GetFullPath(installRoot),
            normalizedStagingRoot,
            Path.Combine(installParent, BackupPrefix + transactionId),
            Directory.Exists(installRoot),
            deleteActivatedDirectoryOnCommit,
            recoveryMetadata);
        Validate(journal, installRoot);
        return journal;
    }

    public static void CreateNew(
        string journalPath,
        string expectedInstallRoot,
        InstallerTransactionJournal journal,
        InstallerOperationLease lease)
    {
        ValidateAccess(journalPath, expectedInstallRoot, journal, lease);
        Publish(journalPath, journal, overwrite: false);
    }

    public static InstallerTransactionJournal Read(
        string journalPath,
        string expectedInstallRoot,
        InstallerOperationLease lease)
    {
        lease.DemandProtects(journalPath);
        RejectReparsePointIfPresent(journalPath);
        var info = new FileInfo(journalPath);
        if (!info.Exists || info.Length <= 0 || info.Length > MaximumJournalBytes)
        {
            throw new InvalidDataException("The setup transaction journal has an invalid size.");
        }

        using var stream = new FileStream(
            journalPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 16 * 1024,
            FileOptions.SequentialScan);
        var journal = JsonSerializer.Deserialize<InstallerTransactionJournal>(stream, JsonOptions)
            ?? throw new InvalidDataException("The setup transaction journal is empty.");
        Validate(journal, expectedInstallRoot);
        return journal;
    }

    public static InstallerTransactionJournal AdvancePhase(
        string journalPath,
        string expectedInstallRoot,
        string expectedTransactionId,
        InstallerTransactionPhase expectedPhase,
        InstallerTransactionPhase nextPhase,
        InstallerOperationLease lease)
    {
        var current = Read(journalPath, expectedInstallRoot, lease);
        DemandExpected(current, expectedTransactionId, expectedPhase);
        if (!IsAllowedTransition(expectedPhase, nextPhase))
        {
            throw new InvalidOperationException("The requested setup transaction phase transition is invalid.");
        }

        var updated = current with { Phase = nextPhase };
        ValidateAccess(journalPath, expectedInstallRoot, updated, lease);
        Publish(journalPath, updated, overwrite: true);
        return updated;
    }

    public static void DeleteExpected(
        string journalPath,
        string expectedInstallRoot,
        string expectedTransactionId,
        InstallerTransactionPhase requiredPhase,
        InstallerOperationLease lease)
    {
        if (requiredPhase is not InstallerTransactionPhase.Committed and
            not InstallerTransactionPhase.FilesRolledBack)
        {
            throw new InvalidOperationException("Setup cannot delete a journal before commit or rollback completion.");
        }
        var current = Read(journalPath, expectedInstallRoot, lease);
        DemandExpected(current, expectedTransactionId, requiredPhase);
        RejectReparsePointIfPresent(journalPath);
        File.Delete(journalPath);
    }

    private static void ValidateAccess(
        string journalPath,
        string expectedInstallRoot,
        InstallerTransactionJournal journal,
        InstallerOperationLease lease)
    {
        lease.DemandProtects(journalPath);
        Validate(journal, expectedInstallRoot);
        var expectedParent = Directory.GetParent(Path.GetFullPath(expectedInstallRoot))?.FullName
            ?? throw new InvalidDataException("The installation directory has no parent.");
        var journalParent = Directory.GetParent(Path.GetFullPath(journalPath))?.FullName
            ?? throw new InvalidDataException("The setup transaction journal has no parent.");
        if (!PathEquals(expectedParent, journalParent))
        {
            throw new UnauthorizedAccessException("The setup transaction journal is outside the installation parent.");
        }
    }

    private static void Publish(
        string journalPath,
        InstallerTransactionJournal journal,
        bool overwrite)
    {
        var parent = Directory.GetParent(Path.GetFullPath(journalPath))?.FullName
            ?? throw new InvalidDataException("The setup transaction journal has no parent.");
        Directory.CreateDirectory(parent);
        RejectReparsePointIfPresent(parent);
        RejectReparsePointIfPresent(journalPath);

        var temporaryPath = Path.Combine(parent, $".journal-{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 16 * 1024,
                       FileOptions.WriteThrough))
            {
                JsonSerializer.Serialize(stream, journal, JsonOptions);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporaryPath, journalPath, overwrite);
        }
        finally
        {
            TryDeleteTemporaryFile(temporaryPath);
        }
    }

    private static void DemandExpected(
        InstallerTransactionJournal journal,
        string expectedTransactionId,
        InstallerTransactionPhase expectedPhase)
    {
        if (!string.Equals(journal.TransactionId, expectedTransactionId, StringComparison.Ordinal) ||
            journal.Phase != expectedPhase)
        {
            throw new InvalidOperationException("The setup transaction journal changed unexpectedly.");
        }
    }

    private static bool IsAllowedTransition(
        InstallerTransactionPhase current,
        InstallerTransactionPhase next) =>
        (current, next) switch
        {
            (InstallerTransactionPhase.Prepared, InstallerTransactionPhase.OldInstallationMoved) => true,
            (InstallerTransactionPhase.Prepared, InstallerTransactionPhase.NewInstallationActivated) => true,
            (InstallerTransactionPhase.Prepared, InstallerTransactionPhase.RollbackStarted) => true,
            (InstallerTransactionPhase.OldInstallationMoved, InstallerTransactionPhase.NewInstallationActivated) => true,
            (InstallerTransactionPhase.OldInstallationMoved, InstallerTransactionPhase.RollbackStarted) => true,
            (InstallerTransactionPhase.NewInstallationActivated, InstallerTransactionPhase.RollbackStarted) => true,
            (InstallerTransactionPhase.NewInstallationActivated, InstallerTransactionPhase.Committed) => true,
            (InstallerTransactionPhase.RollbackStarted, InstallerTransactionPhase.FilesRolledBack) => true,
            _ => false,
        };

    private static void Validate(InstallerTransactionJournal journal, string expectedInstallRoot)
    {
        if (journal.SchemaVersion != CurrentSchemaVersion ||
            !Enum.IsDefined(journal.Phase) ||
            !Guid.TryParseExact(journal.TransactionId, "N", out _))
        {
            throw new InvalidDataException("The setup transaction journal schema is invalid.");
        }
        if (journal.RecoveryMetadata is null ||
            journal.RecoveryMetadata.Length > MaximumRecoveryMetadataCharacters)
        {
            throw new InvalidDataException("The setup transaction recovery metadata is invalid.");
        }

        var normalizedExpectedRoot = Path.GetFullPath(expectedInstallRoot);
        var normalizedInstallRoot = Path.GetFullPath(journal.InstallRoot);
        if (!PathEquals(normalizedExpectedRoot, normalizedInstallRoot))
        {
            throw new UnauthorizedAccessException("The setup transaction targets an unexpected installation path.");
        }

        var installParent = Directory.GetParent(normalizedExpectedRoot)?.FullName
            ?? throw new InvalidDataException("The installation directory has no parent.");
        ValidateTransactionDirectory(
            journal.StagingRoot,
            installParent,
            StagingPrefix + journal.TransactionId);
        ValidateTransactionDirectory(
            journal.BackupRoot,
            installParent,
            BackupPrefix + journal.TransactionId);
        if (PathEquals(journal.StagingRoot, journal.BackupRoot) ||
            PathEquals(journal.StagingRoot, normalizedInstallRoot) ||
            PathEquals(journal.BackupRoot, normalizedInstallRoot))
        {
            throw new InvalidDataException("The setup transaction paths overlap.");
        }
    }

    private static void ValidateTransactionDirectory(
        string candidate,
        string expectedParent,
        string expectedName)
    {
        var normalizedCandidate = Path.GetFullPath(candidate);
        var parent = Directory.GetParent(normalizedCandidate)?.FullName;
        if (!PathEquals(parent ?? string.Empty, expectedParent) ||
            !string.Equals(Path.GetFileName(normalizedCandidate), expectedName, StringComparison.Ordinal))
        {
            throw new UnauthorizedAccessException("The setup transaction directory is outside the installation parent.");
        }
        if (File.Exists(normalizedCandidate) && !Directory.Exists(normalizedCandidate))
        {
            throw new UnauthorizedAccessException("A setup transaction directory is occupied by a file.");
        }
    }

    private static void RejectReparsePointIfPresent(string path)
    {
        if ((File.Exists(path) || Directory.Exists(path)) &&
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new UnauthorizedAccessException("Setup does not use a symbolic link or reparse point for transaction state.");
        }
    }

    private static void TryDeleteTemporaryFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Preserve the journal operation failure; abandoned temp files are never recovery inputs.
        }
    }

    private static bool PathEquals(string left, string right) =>
        string.Equals(Path.GetFullPath(left), Path.GetFullPath(right), StringComparison.OrdinalIgnoreCase);
}
