namespace JTS.WindowsCompanion.Setup;

internal static class InstallerResidueScavenger
{
    private const string StagingPrefix = ".setup-";
    private const string JournalTemporaryPrefix = ".journal-";
    private const string JournalTemporarySuffix = ".tmp";

    public static void CleanupBeforeTransaction(
        string installParent,
        string journalPath,
        InstallerOperationLease lease)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(installParent);
        ArgumentException.ThrowIfNullOrWhiteSpace(journalPath);
        ArgumentNullException.ThrowIfNull(lease);

        var normalizedParent = Path.GetFullPath(installParent);
        var normalizedJournal = Path.GetFullPath(journalPath);
        lease.DemandProtects(normalizedJournal);
        if (!string.Equals(
                Directory.GetParent(normalizedJournal)?.FullName,
                normalizedParent,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException(
                "The setup transaction journal is outside the installation parent.");
        }
        if (File.Exists(normalizedJournal) || Directory.Exists(normalizedJournal))
        {
            throw new InvalidOperationException(
                "Setup cannot scavenge transaction residue while a journal is pending.");
        }
        if (!Directory.Exists(normalizedParent))
        {
            return;
        }
        if ((File.GetAttributes(normalizedParent) & FileAttributes.ReparsePoint) != 0)
        {
            throw new UnauthorizedAccessException(
                "Setup does not scavenge through a reparse-point installation parent.");
        }

        foreach (var entry in Directory.EnumerateFileSystemEntries(normalizedParent))
        {
            var name = Path.GetFileName(entry);
            if (IsGeneratedName(name, StagingPrefix, suffix: string.Empty))
            {
                DeleteStagingDirectory(entry);
            }
            else if (IsGeneratedName(
                         name,
                         JournalTemporaryPrefix,
                         JournalTemporarySuffix))
            {
                DeleteJournalTemporaryFile(entry);
            }
        }
    }

    private static void DeleteStagingDirectory(string path)
    {
        if (!Directory.Exists(path) || File.Exists(path))
        {
            throw new UnauthorizedAccessException(
                "A generated setup staging path is not a directory.");
        }
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new UnauthorizedAccessException(
                "Setup does not remove a reparse-point staging directory.");
        }

        InstallerLayout.DeleteDirectoryWithoutFollowingLinks(path);
    }

    private static void DeleteJournalTemporaryFile(string path)
    {
        if (!File.Exists(path) || Directory.Exists(path))
        {
            throw new UnauthorizedAccessException(
                "A generated setup journal temporary path is not a file.");
        }
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new UnauthorizedAccessException(
                "Setup does not remove a reparse-point journal temporary file.");
        }

        File.Delete(path);
    }

    private static bool IsGeneratedName(
        string name,
        string prefix,
        string suffix)
    {
        if (!name.StartsWith(prefix, StringComparison.Ordinal) ||
            !name.EndsWith(suffix, StringComparison.Ordinal))
        {
            return false;
        }

        var identifierLength = name.Length - prefix.Length - suffix.Length;
        return identifierLength == 32 &&
               Guid.TryParseExact(name.Substring(prefix.Length, identifierLength), "N", out _);
    }
}
