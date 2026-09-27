using System.ComponentModel;
using JTS.WindowsCompanion.Setup;

namespace JTS.WindowsCompanion.Tests;

public sealed class CompanionProcessControllerTests
{
    private const string CurrentUserSid = "S-1-5-21-1000";

    [Fact]
    public void AgentStartInfo_AddsReadinessOnlyToTheOneShotLaunch()
    {
        var layout = new InstallerLayout();
        var controller = new CompanionProcessController(
            layout,
            new FakeCompanionProcessAccess(CurrentUserSid));
        var pipeName = JTS.WindowsCompanion.Lifecycle.CompanionAgentReadinessContract.CreatePipeName();

        var startInfo = controller.CreateAgentStartInfo(pipeName);

        Assert.Contains(
            JTS.WindowsCompanion.Lifecycle.CompanionAgentReadinessContract.ArgumentName,
            startInfo.ArgumentList);
        Assert.Contains(pipeName, startInfo.ArgumentList);
        Assert.DoesNotContain(
            JTS.WindowsCompanion.Lifecycle.CompanionAgentReadinessContract.ArgumentName,
            controller.AgentCommandLine(),
            StringComparison.Ordinal);
    }

    [Fact]
    public void AgentStartInfo_RejectsAnUntrustedReadinessPipeName()
    {
        var controller = new CompanionProcessController(
            new InstallerLayout(),
            new FakeCompanionProcessAccess(CurrentUserSid));

        Assert.Throws<ArgumentException>(() =>
            controller.CreateAgentStartInfo("untrusted-pipe"));
    }

    [Fact]
    public void Prepare_IdentifiesAllTargetsBeforeExecuteAndStopsAgentBeforeBroker()
    {
        var layout = new InstallerLayout();
        var access = new FakeCompanionProcessAccess(CurrentUserSid);
        access.Add(101, InstallerLayout.AgentFileName, layout.AgentPath, CurrentUserSid);
        access.Add(102, InstallerLayout.AgentFileName, layout.AgentPath, CurrentUserSid);
        access.Add(201, InstallerLayout.BrokerFileName, layout.BrokerPath, CurrentUserSid);
        var controller = new CompanionProcessController(layout, access);

        using var prepared = controller.PrepareStopInstalledProcesses();

        Assert.True(prepared.State.AgentWasRunning);
        Assert.True(prepared.State.BrokerWasRunning);
        Assert.Empty(access.StopActions);

        prepared.Execute();

        Assert.Equal(
            [
                "close:101",
                "terminate:101",
                "wait:101",
                "close:102",
                "terminate:102",
                "wait:102",
                "close:201",
                "terminate:201",
                "wait:201",
            ],
            access.StopActions);
    }

    [Fact]
    public void Prepare_IgnoresDifferentPathAndUninspectableSameNameProcesses()
    {
        var layout = new InstallerLayout();
        var access = new FakeCompanionProcessAccess(CurrentUserSid);
        access.Add(
            101,
            InstallerLayout.AgentFileName,
            layout.AgentPath + ".unrelated",
            CurrentUserSid);
        access.Add(
            102,
            InstallerLayout.AgentFileName,
            layout.AgentPath,
            CurrentUserSid,
            queryOpenStatus: CompanionProcessOpenStatus.AccessDenied);
        access.Add(
            103,
            InstallerLayout.AgentFileName,
            layout.AgentPath,
            CurrentUserSid,
            queryPathException: new Win32Exception(5));
        var controller = new CompanionProcessController(layout, access);

        using var prepared = controller.PrepareStopInstalledProcesses();
        prepared.Execute();

        Assert.False(prepared.State.AgentWasRunning);
        Assert.False(prepared.State.BrokerWasRunning);
        Assert.Empty(access.StopActions);
        Assert.Empty(access.StopOpenProcessIds);
    }

    [Fact]
    public void Prepare_RejectsExactInstalledPathOwnedByAnotherAccount()
    {
        var layout = new InstallerLayout();
        var access = new FakeCompanionProcessAccess(CurrentUserSid);
        access.Add(
            101,
            InstallerLayout.AgentFileName,
            layout.AgentPath,
            "S-1-5-21-2000");
        var controller = new CompanionProcessController(layout, access);

        var exception = Assert.Throws<InvalidOperationException>(
            controller.PrepareStopInstalledProcesses);

        Assert.Contains("another Windows account", exception.Message, StringComparison.Ordinal);
        Assert.Empty(access.StopOpenProcessIds);
        Assert.Empty(access.StopActions);
    }

    [Fact]
    public void Prepare_FailsClosedWhenExactInstalledPathOwnerCannotBeVerified()
    {
        var layout = new InstallerLayout();
        var access = new FakeCompanionProcessAccess(CurrentUserSid);
        access.Add(
            101,
            InstallerLayout.AgentFileName,
            layout.AgentPath,
            CurrentUserSid,
            queryOwnerException: new Win32Exception(5));
        var controller = new CompanionProcessController(layout, access);

        var exception = Assert.Throws<InvalidOperationException>(
            controller.PrepareStopInstalledProcesses);

        Assert.Contains("could not verify its Windows account", exception.Message, StringComparison.Ordinal);
        Assert.Empty(access.StopOpenProcessIds);
        Assert.Empty(access.StopActions);
    }

    [Fact]
    public void Prepare_AcquiresEveryStopHandleBeforeStoppingAndLeavesAllRunningOnAccessDenied()
    {
        var layout = new InstallerLayout();
        var access = new FakeCompanionProcessAccess(CurrentUserSid);
        access.Add(101, InstallerLayout.AgentFileName, layout.AgentPath, CurrentUserSid);
        access.Add(
            201,
            InstallerLayout.BrokerFileName,
            layout.BrokerPath,
            CurrentUserSid,
            stopOpenStatus: CompanionProcessOpenStatus.AccessDenied);
        var controller = new CompanionProcessController(layout, access);

        var exception = Assert.Throws<InvalidOperationException>(
            controller.PrepareStopInstalledProcesses);

        Assert.Contains("elevated or protected permissions", exception.Message, StringComparison.Ordinal);
        Assert.Equal([101, 201], access.StopOpenProcessIds);
        Assert.Empty(access.StopActions);
    }

    [Fact]
    public void Prepare_RevalidatesPathOnStopHandleAndNeverStopsChangedIdentity()
    {
        var layout = new InstallerLayout();
        var access = new FakeCompanionProcessAccess(CurrentUserSid);
        access.Add(
            101,
            InstallerLayout.AgentFileName,
            layout.AgentPath,
            CurrentUserSid,
            stopPath: layout.AgentPath + ".changed");
        var controller = new CompanionProcessController(layout, access);

        var exception = Assert.Throws<InvalidOperationException>(
            controller.PrepareStopInstalledProcesses);

        Assert.Contains("identity changed", exception.Message, StringComparison.Ordinal);
        Assert.Empty(access.StopActions);
    }

    [Fact]
    public void Prepare_PreservesPriorStateWhenProcessExitsBeforeStopHandleOpens()
    {
        var layout = new InstallerLayout();
        var access = new FakeCompanionProcessAccess(CurrentUserSid);
        access.Add(
            101,
            InstallerLayout.AgentFileName,
            layout.AgentPath,
            CurrentUserSid,
            stopOpenStatus: CompanionProcessOpenStatus.NotFound);
        var controller = new CompanionProcessController(layout, access);

        using var prepared = controller.PrepareStopInstalledProcesses();
        prepared.Execute();

        Assert.True(prepared.State.AgentWasRunning);
        Assert.Empty(access.StopActions);
    }

    [Fact]
    public void Prepare_TreatsExitDuringStopHandleRevalidationAsSuccess()
    {
        var layout = new InstallerLayout();
        var access = new FakeCompanionProcessAccess(CurrentUserSid);
        access.Add(
            101,
            InstallerLayout.AgentFileName,
            layout.AgentPath,
            CurrentUserSid,
            stopPathException: new Win32Exception(87),
            exitWhenStopPathQueried: true);
        var controller = new CompanionProcessController(layout, access);

        using var prepared = controller.PrepareStopInstalledProcesses();
        prepared.Execute();

        Assert.True(prepared.State.AgentWasRunning);
        Assert.Empty(access.StopActions);
    }

    [Fact]
    public void Execute_WaitsForGracefulCloseAndDoesNotTerminateAfterExit()
    {
        var layout = new InstallerLayout();
        var access = new FakeCompanionProcessAccess(CurrentUserSid);
        access.Add(
            101,
            InstallerLayout.AgentFileName,
            layout.AgentPath,
            CurrentUserSid,
            closeRequested: true,
            waitResults: [true]);
        var controller = new CompanionProcessController(layout, access);

        using var prepared = controller.PrepareStopInstalledProcesses();
        prepared.Execute();

        Assert.Equal(["close:101", "wait:101"], access.StopActions);
    }

    [Fact]
    public void Execute_DoesNotSpendGracefulWaitOnHeadlessProcess()
    {
        var layout = new InstallerLayout();
        var access = new FakeCompanionProcessAccess(CurrentUserSid);
        access.Add(101, InstallerLayout.AgentFileName, layout.AgentPath, CurrentUserSid);
        var controller = new CompanionProcessController(layout, access);

        using var prepared = controller.PrepareStopInstalledProcesses();
        prepared.Execute();

        Assert.Equal(["close:101", "terminate:101", "wait:101"], access.StopActions);
    }

    [Fact]
    public void Execute_AggregatesStopFailureAfterStateWasMadeAvailable()
    {
        var layout = new InstallerLayout();
        var access = new FakeCompanionProcessAccess(CurrentUserSid);
        access.Add(
            101,
            InstallerLayout.AgentFileName,
            layout.AgentPath,
            CurrentUserSid,
            terminateException: new Win32Exception(5));
        var controller = new CompanionProcessController(layout, access);

        using var prepared = controller.PrepareStopInstalledProcesses();
        Assert.True(prepared.State.AgentWasRunning);

        var exception = Assert.Throws<AggregateException>(prepared.Execute);

        Assert.Contains("did not stop", exception.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Execute_CannotRunTwice()
    {
        var layout = new InstallerLayout();
        var access = new FakeCompanionProcessAccess(CurrentUserSid);
        var controller = new CompanionProcessController(layout, access);
        using var prepared = controller.PrepareStopInstalledProcesses();

        prepared.Execute();

        Assert.Throws<InvalidOperationException>(prepared.Execute);
    }

    private sealed class FakeCompanionProcessAccess : ICompanionProcessAccess
    {
        private readonly List<FakeProcess> _processes = [];

        public FakeCompanionProcessAccess(string currentUserSid)
        {
            CurrentUserSid = currentUserSid;
        }

        public string CurrentUserSid { get; }

        public List<int> StopOpenProcessIds { get; } = [];

        public List<string> StopActions { get; } = [];

        public void Add(
            int processId,
            string fileName,
            string path,
            string ownerSid,
            CompanionProcessOpenStatus queryOpenStatus = CompanionProcessOpenStatus.Opened,
            CompanionProcessOpenStatus stopOpenStatus = CompanionProcessOpenStatus.Opened,
            Exception? queryPathException = null,
            Exception? queryOwnerException = null,
            string? stopPath = null,
            Exception? stopPathException = null,
            bool exitWhenStopPathQueried = false,
            string? stopOwnerSid = null,
            bool closeRequested = false,
            IReadOnlyList<bool>? waitResults = null,
            Exception? terminateException = null)
        {
            _processes.Add(new FakeProcess(
                processId,
                Path.GetFileNameWithoutExtension(fileName),
                path,
                ownerSid,
                queryOpenStatus,
                stopOpenStatus,
                queryPathException,
                queryOwnerException,
                stopPath,
                stopPathException,
                exitWhenStopPathQueried,
                stopOwnerSid,
                closeRequested,
                new Queue<bool>(waitResults ?? []),
                terminateException));
        }

        public IReadOnlyList<int> EnumerateProcessIds(string processName) =>
            _processes
                .Where(process => string.Equals(
                    process.ProcessName,
                    processName,
                    StringComparison.OrdinalIgnoreCase))
                .Select(process => process.ProcessId)
                .ToArray();

        public CompanionProcessOpenResult<ICompanionProcessQueryHandle> OpenForQuery(int processId)
        {
            var process = Find(processId);
            return process.QueryOpenStatus == CompanionProcessOpenStatus.Opened
                ? CompanionProcessOpenResult<ICompanionProcessQueryHandle>.Opened(
                    new FakeProcessHandle(process, StopActions, stopHandle: false))
                : CompanionProcessOpenResult<ICompanionProcessQueryHandle>.Failed(
                    process.QueryOpenStatus,
                    ErrorCode(process.QueryOpenStatus));
        }

        public CompanionProcessOpenResult<ICompanionProcessStopHandle> OpenForStop(int processId)
        {
            StopOpenProcessIds.Add(processId);
            var process = Find(processId);
            return process.StopOpenStatus == CompanionProcessOpenStatus.Opened
                ? CompanionProcessOpenResult<ICompanionProcessStopHandle>.Opened(
                    new FakeProcessHandle(process, StopActions, stopHandle: true))
                : CompanionProcessOpenResult<ICompanionProcessStopHandle>.Failed(
                    process.StopOpenStatus,
                    ErrorCode(process.StopOpenStatus));
        }

        private FakeProcess Find(int processId) =>
            _processes.Single(process => process.ProcessId == processId);

        private static int ErrorCode(CompanionProcessOpenStatus status) => status switch
        {
            CompanionProcessOpenStatus.AccessDenied => 5,
            CompanionProcessOpenStatus.NotFound => 87,
            _ => 31,
        };
    }

    private sealed class FakeProcessHandle : ICompanionProcessStopHandle
    {
        private readonly FakeProcess _process;
        private readonly ICollection<string> _actions;
        private readonly bool _stopHandle;

        public FakeProcessHandle(
            FakeProcess process,
            ICollection<string> actions,
            bool stopHandle)
        {
            _process = process;
            _actions = actions;
            _stopHandle = stopHandle;
        }

        public int ProcessId => _process.ProcessId;

        public bool HasExited => _stopHandle
            ? _process.StopExited
            : _process.QueryExited;

        public string QueryImagePath()
        {
            if (!_stopHandle && _process.QueryPathException is not null)
            {
                throw _process.QueryPathException;
            }
            if (_stopHandle && _process.StopPathException is not null)
            {
                _process.StopExited = _process.ExitWhenStopPathQueried;
                throw _process.StopPathException;
            }
            return _stopHandle && _process.StopPath is not null
                ? _process.StopPath
                : _process.Path;
        }

        public string QueryOwnerSid()
        {
            if (!_stopHandle && _process.QueryOwnerException is not null)
            {
                throw _process.QueryOwnerException;
            }
            return _stopHandle && _process.StopOwnerSid is not null
                ? _process.StopOwnerSid
                : _process.OwnerSid;
        }

        public bool RequestClose()
        {
            EnsureStopHandle();
            _actions.Add($"close:{ProcessId}");
            return _process.CloseRequested;
        }

        public bool WaitForExit(TimeSpan timeout)
        {
            EnsureStopHandle();
            Assert.Equal(TimeSpan.FromSeconds(5), timeout);
            _actions.Add($"wait:{ProcessId}");
            var result = _process.WaitResults.Count > 0
                ? _process.WaitResults.Dequeue()
                : _process.StopExited;
            if (result)
            {
                _process.StopExited = true;
            }
            return result;
        }

        public void Terminate()
        {
            EnsureStopHandle();
            _actions.Add($"terminate:{ProcessId}");
            if (_process.TerminateException is not null)
            {
                throw _process.TerminateException;
            }
            _process.StopExited = true;
        }

        public void Dispose()
        {
        }

        private void EnsureStopHandle()
        {
            if (!_stopHandle)
            {
                throw new InvalidOperationException("A query-only fake handle cannot stop a process.");
            }
        }
    }

    private sealed record FakeProcess(
        int ProcessId,
        string ProcessName,
        string Path,
        string OwnerSid,
        CompanionProcessOpenStatus QueryOpenStatus,
        CompanionProcessOpenStatus StopOpenStatus,
        Exception? QueryPathException,
        Exception? QueryOwnerException,
        string? StopPath,
        Exception? StopPathException,
        bool ExitWhenStopPathQueried,
        string? StopOwnerSid,
        bool CloseRequested,
        Queue<bool> WaitResults,
        Exception? TerminateException)
    {
        public bool QueryExited { get; set; }

        public bool StopExited { get; set; }
    }
}
