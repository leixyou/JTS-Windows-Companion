using JTS.WindowsCompanion.Setup;

namespace JTS.WindowsCompanion.Tests;

internal sealed class TransactionTestLayout : IDisposable
{
    public TransactionTestLayout(bool createStagingDirectory = true)
    {
        Root = Path.Combine(Path.GetTempPath(), $"jts-setup-transaction-{Guid.NewGuid():N}");
        InstallRoot = Path.Combine(Root, "Windows Companion");
        StagingRoot = Path.Combine(Root, $".setup-{Guid.NewGuid():N}");
        JournalPath = Path.Combine(Root, ".transaction.json");
        OperationLockPath = Path.Combine(Root, ".jts-windows-companion-setup.lock");
        var stateRoot = Path.Combine(Root, "state");
        StateFile = Path.Combine(stateRoot, "identity.v1.json");
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(stateRoot);
        File.WriteAllText(StateFile, "paired-state");
        if (createStagingDirectory)
        {
            Directory.CreateDirectory(StagingRoot);
        }
    }

    public string Root { get; }
    public string InstallRoot { get; }
    public string StagingRoot { get; }
    public string JournalPath { get; }
    public string OperationLockPath { get; }
    public string StateFile { get; }

    public InstallerOperationLease AcquireLease(TimeSpan? timeout = null) =>
        InstallerOperationLease.TryAcquire(
            OperationLockPath,
            timeout ?? TimeSpan.Zero)
        ?? throw new InvalidOperationException("The test setup operation lease is already held.");

    public void CreateExistingInstallation()
    {
        Directory.CreateDirectory(InstallRoot);
        File.WriteAllText(Path.Combine(InstallRoot, "agent.exe"), "old-agent");
        File.WriteAllText(Path.Combine(InstallRoot, "old-only.txt"), "old-only");
    }

    public void CreateStagedInstallation()
    {
        Directory.CreateDirectory(StagingRoot);
        File.WriteAllText(Path.Combine(StagingRoot, "agent.exe"), "new-agent");
        File.WriteAllText(Path.Combine(StagingRoot, "broker.exe"), "new-broker");
        File.WriteAllText(Path.Combine(StagingRoot, "setup.exe"), "new-setup");
    }

    public string ReadInstalled(string fileName) =>
        File.ReadAllText(Path.Combine(InstallRoot, fileName));

    public void Dispose()
    {
        if (Directory.Exists(Root))
        {
            Directory.Delete(Root, recursive: true);
        }
    }
}
