using System.Diagnostics;
using JTS.WindowsCompanion.Setup;

namespace JTS.WindowsCompanion.Tests;

public sealed class InstallerTransactionConcurrencyTests
{
    private const string LeaseProbePathVariable = "JTS_SETUP_LEASE_PROBE_PATH";

    [Fact]
    public void OperationLease_AllowsOnlyOneCrossProcessHolderAndPersistsAcrossReacquisition()
    {
        using var layout = new TransactionTestLayout();
        var first = layout.AcquireLease();
        try
        {
            Assert.True(File.Exists(layout.OperationLockPath));
            Assert.Null(
                InstallerOperationLease.TryAcquire(
                    layout.OperationLockPath,
                    TimeSpan.Zero));
            RunCrossProcessLeaseProbe(layout.OperationLockPath);
        }
        finally
        {
            first.Dispose();
        }

        Assert.True(File.Exists(layout.OperationLockPath));
        using var reacquired = layout.AcquireLease();
        reacquired.DemandProtects(layout.JournalPath);
    }

    [Fact]
    public void OperationLease_CrossProcessProbe()
    {
        var lockPath = Environment.GetEnvironmentVariable(LeaseProbePathVariable);
        if (string.IsNullOrWhiteSpace(lockPath))
        {
            using var layout = new TransactionTestLayout();
            using var lease = layout.AcquireLease();
            Assert.NotNull(lease);
            return;
        }

        Assert.Null(InstallerOperationLease.TryAcquire(lockPath, TimeSpan.Zero));
    }

    [Fact]
    public void CreateNew_DoesNotOverwriteAnExistingTransactionJournal()
    {
        using var layout = new TransactionTestLayout();
        using var lease = layout.AcquireLease();
        layout.CreateStagedInstallation();
        _ = InstallerDirectoryTransaction.Begin(
            layout.InstallRoot,
            layout.StagingRoot,
            layout.JournalPath,
            "first-transaction",
            lease);
        var original = InstallerTransactionJournalStore.Read(
            layout.JournalPath,
            layout.InstallRoot,
            lease);
        var secondStagingRoot = Path.Combine(layout.Root, $".setup-{Guid.NewGuid():N}");
        Directory.CreateDirectory(secondStagingRoot);
        var replacement = InstallerTransactionJournalStore.Create(
            layout.InstallRoot,
            secondStagingRoot,
            deleteActivatedDirectoryOnCommit: false,
            recoveryMetadata: "second-transaction");

        Assert.Throws<IOException>(
            () => InstallerTransactionJournalStore.CreateNew(
                layout.JournalPath,
                layout.InstallRoot,
                replacement,
                lease));

        var retained = InstallerTransactionJournalStore.Read(
            layout.JournalPath,
            layout.InstallRoot,
            lease);
        Assert.Equal(original.TransactionId, retained.TransactionId);
        Assert.Equal("first-transaction", retained.RecoveryMetadata);
    }

    [Fact]
    public void AdvancePhase_RejectsForeignTransactionIdWithoutMutation()
    {
        using var layout = new TransactionTestLayout();
        using var lease = layout.AcquireLease();
        layout.CreateStagedInstallation();
        _ = InstallerDirectoryTransaction.Begin(
            layout.InstallRoot,
            layout.StagingRoot,
            layout.JournalPath,
            "registration",
            lease);

        Assert.Throws<InvalidOperationException>(
            () => InstallerTransactionJournalStore.AdvancePhase(
                layout.JournalPath,
                layout.InstallRoot,
                Guid.NewGuid().ToString("N"),
                InstallerTransactionPhase.Prepared,
                InstallerTransactionPhase.NewInstallationActivated,
                lease));

        var retained = InstallerTransactionJournalStore.Read(
            layout.JournalPath,
            layout.InstallRoot,
            lease);
        Assert.Equal(InstallerTransactionPhase.Prepared, retained.Phase);
    }

    [Fact]
    public void AdvancePhase_RejectsAStaleExpectedPhaseWithoutMutation()
    {
        using var layout = new TransactionTestLayout();
        using var lease = layout.AcquireLease();
        layout.CreateStagedInstallation();
        _ = InstallerDirectoryTransaction.Begin(
            layout.InstallRoot,
            layout.StagingRoot,
            layout.JournalPath,
            "registration",
            lease);
        var journal = InstallerTransactionJournalStore.Read(
            layout.JournalPath,
            layout.InstallRoot,
            lease);
        Directory.Move(layout.StagingRoot, layout.InstallRoot);
        _ = InstallerTransactionJournalStore.AdvancePhase(
            layout.JournalPath,
            layout.InstallRoot,
            journal.TransactionId,
            InstallerTransactionPhase.Prepared,
            InstallerTransactionPhase.NewInstallationActivated,
            lease);

        Assert.Throws<InvalidOperationException>(
            () => InstallerTransactionJournalStore.AdvancePhase(
                layout.JournalPath,
                layout.InstallRoot,
                journal.TransactionId,
                InstallerTransactionPhase.Prepared,
                InstallerTransactionPhase.RollbackStarted,
                lease));

        var retained = InstallerTransactionJournalStore.Read(
            layout.JournalPath,
            layout.InstallRoot,
            lease);
        Assert.Equal(InstallerTransactionPhase.NewInstallationActivated, retained.Phase);
    }

    [Fact]
    public void AdvancePhase_RejectsAnIllegalTransitionWithoutMutation()
    {
        using var layout = new TransactionTestLayout();
        using var lease = layout.AcquireLease();
        layout.CreateStagedInstallation();
        _ = InstallerDirectoryTransaction.Begin(
            layout.InstallRoot,
            layout.StagingRoot,
            layout.JournalPath,
            "registration",
            lease);
        var journal = InstallerTransactionJournalStore.Read(
            layout.JournalPath,
            layout.InstallRoot,
            lease);

        Assert.Throws<InvalidOperationException>(
            () => InstallerTransactionJournalStore.AdvancePhase(
                layout.JournalPath,
                layout.InstallRoot,
                journal.TransactionId,
                InstallerTransactionPhase.Prepared,
                InstallerTransactionPhase.Committed,
                lease));

        var retained = InstallerTransactionJournalStore.Read(
            layout.JournalPath,
            layout.InstallRoot,
            lease);
        Assert.Equal(InstallerTransactionPhase.Prepared, retained.Phase);
    }

    [Fact]
    public void RecoverPending_RejectsForeignTransactionIdBeforeChangingDirectories()
    {
        using var layout = new TransactionTestLayout();
        using var lease = layout.AcquireLease();
        layout.CreateExistingInstallation();
        layout.CreateStagedInstallation();
        _ = InstallerDirectoryTransaction.Begin(
            layout.InstallRoot,
            layout.StagingRoot,
            layout.JournalPath,
            "registration",
            lease);

        Assert.Throws<InvalidOperationException>(
            () => InstallerDirectoryTransaction.RecoverPending(
                layout.InstallRoot,
                layout.JournalPath,
                lease,
                Guid.NewGuid().ToString("N")));

        Assert.Equal("old-agent", layout.ReadInstalled("agent.exe"));
        Assert.True(Directory.Exists(layout.StagingRoot));
        Assert.True(File.Exists(layout.JournalPath));
    }

    [Fact]
    public void CompletePendingRollback_RejectsForeignTransactionIdAndPreservesJournal()
    {
        using var layout = new TransactionTestLayout();
        using var lease = layout.AcquireLease();
        layout.CreateStagedInstallation();
        _ = InstallerDirectoryTransaction.Begin(
            layout.InstallRoot,
            layout.StagingRoot,
            layout.JournalPath,
            "registration",
            lease);
        var recovery = InstallerDirectoryTransaction.RecoverPending(
            layout.InstallRoot,
            layout.JournalPath,
            lease);

        Assert.Throws<InvalidOperationException>(
            () => InstallerDirectoryTransaction.CompletePendingRollback(
                layout.InstallRoot,
                layout.JournalPath,
                Guid.NewGuid().ToString("N"),
                lease));

        var retained = InstallerTransactionJournalStore.Read(
            layout.JournalPath,
            layout.InstallRoot,
            lease);
        Assert.Equal(recovery.TransactionId, retained.TransactionId);
        Assert.Equal(InstallerTransactionPhase.FilesRolledBack, retained.Phase);
    }

    private static void RunCrossProcessLeaseProbe(string lockPath)
    {
        var dotnetHost = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH");
        if (string.IsNullOrWhiteSpace(dotnetHost))
        {
            dotnetHost = Environment.ProcessPath;
        }
        Assert.False(string.IsNullOrWhiteSpace(dotnetHost));

        var startInfo = new ProcessStartInfo(dotnetHost!)
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };
        startInfo.ArgumentList.Add("vstest");
        startInfo.ArgumentList.Add(typeof(InstallerTransactionConcurrencyTests).Assembly.Location);
        startInfo.ArgumentList.Add(
            $"--Tests:{typeof(InstallerTransactionConcurrencyTests).FullName}.{nameof(OperationLease_CrossProcessProbe)}");
        startInfo.Environment[LeaseProbePathVariable] = lockPath;

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("The cross-process setup lease probe could not start.");
        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(milliseconds: 30_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("The cross-process setup lease probe did not finish.");
        }

        Assert.True(
            process.ExitCode == 0,
            $"The cross-process setup lease probe failed.{Environment.NewLine}" +
            $"stdout:{Environment.NewLine}{standardOutput.GetAwaiter().GetResult()}{Environment.NewLine}" +
            $"stderr:{Environment.NewLine}{standardError.GetAwaiter().GetResult()}");
    }
}
