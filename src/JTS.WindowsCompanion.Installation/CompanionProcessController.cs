using System.ComponentModel;
using System.Diagnostics;
using JTS.WindowsCompanion.Lifecycle;

namespace JTS.WindowsCompanion.Setup;

internal sealed class CompanionProcessController
{
    private readonly InstallerLayout _layout;
    private readonly ICompanionProcessAccess _processAccess;

    public CompanionProcessController(InstallerLayout layout)
        : this(layout, new WindowsCompanionProcessAccess())
    {
    }

    internal CompanionProcessController(
        InstallerLayout layout,
        ICompanionProcessAccess processAccess)
    {
        _layout = layout ?? throw new ArgumentNullException(nameof(layout));
        _processAccess = processAccess ?? throw new ArgumentNullException(nameof(processAccess));
    }

    public bool StopAgent()
    {
        using var prepared = PrepareStopProcesses(new[] { AgentSpecification() });
        var wasRunning = prepared.State.AgentWasRunning;
        prepared.Execute();
        return wasRunning;
    }

    public bool StopBroker()
    {
        using var prepared = PrepareStopProcesses(new[] { BrokerSpecification() });
        var wasRunning = prepared.State.BrokerWasRunning;
        prepared.Execute();
        return wasRunning;
    }

    public PreparedCompanionProcessStop PrepareStopInstalledProcesses() =>
        PrepareStopProcesses(new[] { AgentSpecification(), BrokerSpecification() });

    public int StartAgent(string? startupReadyPipeName = null)
    {
        var startInfo = CreateAgentStartInfo(startupReadyPipeName);
        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("The installed Companion could not be started.");
        try
        {
            return process.Id;
        }
        catch (InvalidOperationException exception)
        {
            throw new InvalidOperationException(
                "The installed Companion process identifier is unavailable.",
                exception);
        }
    }

    internal ProcessStartInfo CreateAgentStartInfo(string? startupReadyPipeName = null)
    {
        if (startupReadyPipeName is not null)
        {
            CompanionAgentReadinessContract.ValidatePipeName(startupReadyPipeName);
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = _layout.AgentPath,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        AddAgentArguments(startInfo.ArgumentList, startupReadyPipeName);
        return startInfo;
    }

    public string AgentCommandLine()
    {
        var arguments = new List<string>();
        AddAgentArguments(arguments, startupReadyPipeName: null);
        return string.Join(
            ' ',
            new[] { WindowsCommandLineArgumentQuoter.Quote(_layout.AgentPath) }
                .Concat(arguments.Select(WindowsCommandLineArgumentQuoter.Quote)));
    }

    private PreparedCompanionProcessStop PrepareStopProcesses(
        IReadOnlyList<InstalledProcessSpecification> specifications)
    {
        var currentUserSid = _processAccess.CurrentUserSid;
        if (string.IsNullOrWhiteSpace(currentUserSid))
        {
            throw new UnauthorizedAccessException("The current Windows user SID is unavailable.");
        }

        var discovered = new List<DiscoveredTarget>();
        var prepared = new List<PreparedCompanionProcessStop.PreparedTarget>();
        try
        {
            DiscoverTargets(specifications, currentUserSid, discovered);
            var state = new CompanionProcessStopState(
                discovered.Any(target => target.Specification.Role == CompanionProcessRole.Agent),
                discovered.Any(target => target.Specification.Role == CompanionProcessRole.Broker));
            AcquireStopHandles(discovered, currentUserSid, prepared);
            return new PreparedCompanionProcessStop(state, prepared.ToArray());
        }
        catch
        {
            foreach (var target in prepared)
            {
                target.Handle.Dispose();
            }
            throw;
        }
        finally
        {
            foreach (var target in discovered)
            {
                target.QueryHandle.Dispose();
            }
        }
    }

    private void DiscoverTargets(
        IReadOnlyList<InstalledProcessSpecification> specifications,
        string currentUserSid,
        ICollection<DiscoveredTarget> discovered)
    {
        foreach (var specification in specifications)
        {
            var processName = Path.GetFileNameWithoutExtension(specification.FileName);
            foreach (var processId in _processAccess.EnumerateProcessIds(processName).Distinct())
            {
                var opened = _processAccess.OpenForQuery(processId);
                if (opened.Status is CompanionProcessOpenStatus.NotFound
                    or CompanionProcessOpenStatus.AccessDenied)
                {
                    continue;
                }
                if (opened.Status != CompanionProcessOpenStatus.Opened || opened.Handle is null)
                {
                    throw ProcessOpenException(
                        specification.FileName,
                        processId,
                        "inspect",
                        opened.NativeErrorCode);
                }

                var handle = opened.Handle;
                var retained = false;
                try
                {
                    if (handle.HasExited
                        || QueryPathMatch(handle, specification.ExpectedPath) != ProcessPathMatch.Match)
                    {
                        continue;
                    }

                    string ownerSid;
                    try
                    {
                        ownerSid = handle.QueryOwnerSid();
                    }
                    catch (Exception exception) when (IsExpectedInspectionFailure(exception))
                    {
                        if (TryHasExited(handle))
                        {
                            continue;
                        }
                        throw new InvalidOperationException(
                            $"Setup identified the installed {specification.FileName} process (PID {processId}) " +
                            "but could not verify its Windows account. Close it before continuing setup.",
                            exception);
                    }

                    if (!string.Equals(ownerSid, currentUserSid, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException(
                            $"The installed {specification.FileName} process (PID {processId}) is running " +
                            "under another Windows account. Close it or sign that account out before continuing setup.");
                    }

                    discovered.Add(new DiscoveredTarget(specification, handle));
                    retained = true;
                }
                finally
                {
                    if (!retained)
                    {
                        handle.Dispose();
                    }
                }
            }
        }
    }

    private void AcquireStopHandles(
        IReadOnlyList<DiscoveredTarget> discovered,
        string currentUserSid,
        ICollection<PreparedCompanionProcessStop.PreparedTarget> prepared)
    {
        foreach (var target in discovered)
        {
            if (target.QueryHandle.HasExited)
            {
                continue;
            }

            var opened = _processAccess.OpenForStop(target.QueryHandle.ProcessId);
            if (opened.Status == CompanionProcessOpenStatus.NotFound)
            {
                continue;
            }
            if (opened.Status == CompanionProcessOpenStatus.AccessDenied)
            {
                throw new InvalidOperationException(
                    $"The installed {target.Specification.FileName} process " +
                    $"(PID {target.QueryHandle.ProcessId}) is running with elevated or protected permissions. " +
                    "Close it from the same Windows account before continuing setup. Setup did not change the installation.",
                    new Win32Exception(opened.NativeErrorCode));
            }
            if (opened.Status != CompanionProcessOpenStatus.Opened || opened.Handle is null)
            {
                throw ProcessOpenException(
                    target.Specification.FileName,
                    target.QueryHandle.ProcessId,
                    "prepare to stop",
                    opened.NativeErrorCode);
            }

            var stopHandle = opened.Handle;
            var retained = false;
            try
            {
                if (stopHandle.HasExited)
                {
                    continue;
                }
                var pathMatch = QueryPathMatch(stopHandle, target.Specification.ExpectedPath);
                if (pathMatch == ProcessPathMatch.Unavailable && TryHasExited(stopHandle))
                {
                    continue;
                }
                if (pathMatch != ProcessPathMatch.Match)
                {
                    throw new InvalidOperationException(
                        $"The {target.Specification.FileName} process identity changed while setup was preparing to stop it.");
                }

                string ownerSid;
                try
                {
                    ownerSid = stopHandle.QueryOwnerSid();
                }
                catch (Exception exception) when (IsExpectedInspectionFailure(exception))
                {
                    if (TryHasExited(stopHandle))
                    {
                        continue;
                    }
                    throw new InvalidOperationException(
                        $"Setup could not revalidate the owner of {target.Specification.FileName} " +
                        $"(PID {stopHandle.ProcessId}) before stopping it.",
                        exception);
                }
                if (!string.Equals(ownerSid, currentUserSid, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException(
                        $"The owner of {target.Specification.FileName} changed while setup was preparing to stop it.");
                }

                prepared.Add(new PreparedCompanionProcessStop.PreparedTarget(
                    target.Specification.Role,
                    target.Specification.FileName,
                    stopHandle));
                retained = true;
            }
            finally
            {
                if (!retained)
                {
                    stopHandle.Dispose();
                }
            }
        }
    }

    private static ProcessPathMatch QueryPathMatch(
        ICompanionProcessQueryHandle handle,
        string expectedPath)
    {
        try
        {
            var processPath = NormalizePath(handle.QueryImagePath());
            return string.Equals(processPath, expectedPath, StringComparison.OrdinalIgnoreCase)
                ? ProcessPathMatch.Match
                : ProcessPathMatch.Mismatch;
        }
        catch (Exception exception) when (IsExpectedInspectionFailure(exception))
        {
            return ProcessPathMatch.Unavailable;
        }
    }

    private static bool TryHasExited(ICompanionProcessQueryHandle handle)
    {
        try
        {
            return handle.HasExited;
        }
        catch (Exception exception) when (IsExpectedInspectionFailure(exception))
        {
            return false;
        }
    }

    private static bool IsExpectedInspectionFailure(Exception exception) =>
        exception is Win32Exception
            or InvalidOperationException
            or UnauthorizedAccessException
            or IOException;

    private static InvalidOperationException ProcessOpenException(
        string fileName,
        int processId,
        string operation,
        int nativeErrorCode) =>
        new(
            $"Setup could not {operation} a same-named {fileName} process (PID {processId}).",
            new Win32Exception(nativeErrorCode));

    private InstalledProcessSpecification AgentSpecification() =>
        new(
            CompanionProcessRole.Agent,
            InstallerLayout.AgentFileName,
            NormalizePath(_layout.AgentPath));

    private InstalledProcessSpecification BrokerSpecification() =>
        new(
            CompanionProcessRole.Broker,
            InstallerLayout.BrokerFileName,
            NormalizePath(_layout.BrokerPath));

    private static string NormalizePath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var normalized = path;
        if (normalized.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            normalized = @"\\" + normalized[8..];
        }
        else if (normalized.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[4..];
        }
        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(normalized));
    }

    private void AddAgentArguments(
        ICollection<string> arguments,
        string? startupReadyPipeName)
    {
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        if (string.IsNullOrWhiteSpace(documents) || string.IsNullOrWhiteSpace(desktop))
        {
            throw new InvalidOperationException("The current user's Documents or Desktop directory is unavailable.");
        }
        arguments.Add("--root");
        arguments.Add($"documents={documents}");
        arguments.Add("--root");
        arguments.Add($"desktop={desktop}");
        arguments.Add("--uac-broker");
        arguments.Add(_layout.BrokerPath);
        if (startupReadyPipeName is not null)
        {
            arguments.Add(CompanionAgentReadinessContract.ArgumentName);
            arguments.Add(startupReadyPipeName);
        }
    }

    private sealed record InstalledProcessSpecification(
        CompanionProcessRole Role,
        string FileName,
        string ExpectedPath);

    private sealed record DiscoveredTarget(
        InstalledProcessSpecification Specification,
        ICompanionProcessQueryHandle QueryHandle);

    private enum ProcessPathMatch
    {
        Match,
        Mismatch,
        Unavailable,
    }
}
