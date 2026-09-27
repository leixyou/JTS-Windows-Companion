using JTS.WindowsCompanion.Lifecycle;

namespace JTS.WindowsCompanion.Tests;

public sealed class CompanionAgentStartupGateTests
{
    [Fact]
    public void OutsideInstalledPath_DoesNotCreateOrWaitOnTheSetupGate()
    {
        using var layout = new StartupGateTestLayout();
        var developmentExecutable = Path.Combine(layout.Root, "development-agent.exe");
        File.WriteAllText(developmentExecutable, "development");

        var result = CompanionAgentStartupGate.WaitForStableInstalledImage(
            developmentExecutable,
            layout.ExecutablePath,
            layout.LockPath,
            TimeSpan.Zero);

        Assert.Equal(CompanionAgentStartupGateResult.Continue, result);
        Assert.False(File.Exists(layout.LockPath));
    }

    [Fact]
    public void StableInstalledImage_ContinuesAndLeavesThePersistentGateFile()
    {
        using var layout = new StartupGateTestLayout();
        layout.WriteExecutable("stable-agent");

        var result = CompanionAgentStartupGate.WaitForStableInstalledImage(
            layout.ExecutablePath,
            layout.ExecutablePath,
            layout.LockPath,
            TimeSpan.Zero);

        Assert.Equal(CompanionAgentStartupGateResult.Continue, result);
        Assert.True(File.Exists(layout.LockPath));
    }

    [Fact]
    public async Task ImageReplacedWhileSetupOwnsGate_ExitsTheSupersededAgent()
    {
        using var layout = new StartupGateTestLayout();
        layout.WriteExecutable("old-agent");
        Directory.CreateDirectory(Path.GetDirectoryName(layout.LockPath)!);
        await using var setupGate = new FileStream(
            layout.LockPath,
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None);

        var waitingAgent = Task.Run(() =>
            CompanionAgentStartupGate.WaitForStableInstalledImage(
                layout.ExecutablePath,
                layout.ExecutablePath,
                layout.LockPath,
                TimeSpan.FromSeconds(5)));
        await Task.Delay(150);
        Assert.False(waitingAgent.IsCompleted);
        layout.ReplaceExecutable("new-agent");

        await setupGate.DisposeAsync();
        var result = await waitingAgent.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(CompanionAgentStartupGateResult.Superseded, result);
    }

    [Fact]
    public void HeldSetupGate_TimesOutWithoutStartingTheAgent()
    {
        using var layout = new StartupGateTestLayout();
        layout.WriteExecutable("stable-agent");
        Directory.CreateDirectory(Path.GetDirectoryName(layout.LockPath)!);
        using var setupGate = new FileStream(
            layout.LockPath,
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None);

        var result = CompanionAgentStartupGate.WaitForStableInstalledImage(
            layout.ExecutablePath,
            layout.ExecutablePath,
            layout.LockPath,
            TimeSpan.FromMilliseconds(100));

        Assert.Equal(CompanionAgentStartupGateResult.TimedOut, result);
    }

    private sealed class StartupGateTestLayout : IDisposable
    {
        public StartupGateTestLayout()
        {
            Root = Path.Combine(Path.GetTempPath(), $"jts-agent-startup-{Guid.NewGuid():N}");
            var installParent = Path.Combine(Root, "JTS Terminal");
            var installRoot = Path.Combine(installParent, "Windows Companion");
            ExecutablePath = Path.Combine(
                installRoot,
                CompanionInstallationContract.AgentFileName);
            LockPath = Path.Combine(
                installParent,
                CompanionInstallationContract.OperationLockFileName);
            Directory.CreateDirectory(installRoot);
        }

        public string Root { get; }

        public string ExecutablePath { get; }

        public string LockPath { get; }

        public void WriteExecutable(string contents) =>
            File.WriteAllText(ExecutablePath, contents);

        public void ReplaceExecutable(string contents)
        {
            var replacement = ExecutablePath + ".replacement";
            File.WriteAllText(replacement, contents);
            File.Move(replacement, ExecutablePath, overwrite: true);
        }

        public void Dispose()
        {
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }
    }
}
