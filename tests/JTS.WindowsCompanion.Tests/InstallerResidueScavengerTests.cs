using JTS.WindowsCompanion.Setup;

namespace JTS.WindowsCompanion.Tests;

public sealed class InstallerResidueScavengerTests
{
    [Fact]
    public void Cleanup_RemovesOnlyStrictGeneratedResidue()
    {
        using var layout = new TransactionTestLayout();
        using var lease = layout.AcquireLease();
        var staging = Path.Combine(layout.Root, $".setup-{Guid.NewGuid():N}");
        var journalTemporary = Path.Combine(layout.Root, $".journal-{Guid.NewGuid():N}.tmp");
        var unrelatedDirectory = Path.Combine(layout.Root, ".setup-not-generated");
        var unrelatedFile = Path.Combine(layout.Root, ".journal-not-generated.tmp");
        Directory.CreateDirectory(staging);
        File.WriteAllText(Path.Combine(staging, "payload.exe"), "payload");
        File.WriteAllText(journalTemporary, "journal");
        Directory.CreateDirectory(unrelatedDirectory);
        File.WriteAllText(unrelatedFile, "keep");

        InstallerResidueScavenger.CleanupBeforeTransaction(
            layout.Root,
            layout.JournalPath,
            lease);

        Assert.False(Directory.Exists(staging));
        Assert.False(File.Exists(journalTemporary));
        Assert.True(Directory.Exists(unrelatedDirectory));
        Assert.True(File.Exists(unrelatedFile));
    }

    [Fact]
    public void Cleanup_RefusesToRunWhileAJournalIsPending()
    {
        using var layout = new TransactionTestLayout();
        using var lease = layout.AcquireLease();
        File.WriteAllText(layout.JournalPath, "pending");
        var staging = Path.Combine(layout.Root, $".setup-{Guid.NewGuid():N}");
        Directory.CreateDirectory(staging);

        Assert.Throws<InvalidOperationException>(() =>
            InstallerResidueScavenger.CleanupBeforeTransaction(
                layout.Root,
                layout.JournalPath,
                lease));

        Assert.True(Directory.Exists(staging));
    }

    [Fact]
    public void Cleanup_RejectsAReparsePointWithAGeneratedStagingName()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var layout = new TransactionTestLayout();
        using var lease = layout.AcquireLease();
        var target = Path.Combine(layout.Root, "target");
        var staging = Path.Combine(layout.Root, $".setup-{Guid.NewGuid():N}");
        Directory.CreateDirectory(target);
        Directory.CreateSymbolicLink(staging, target);

        Assert.Throws<UnauthorizedAccessException>(() =>
            InstallerResidueScavenger.CleanupBeforeTransaction(
                layout.Root,
                layout.JournalPath,
                lease));

        Assert.True(Directory.Exists(target));
    }
}
