namespace JTS.WindowsCompanion.Setup;

internal sealed class CompanionRollbackCoordinator
{
    private readonly InstallerLayout _layout;
    private readonly CompanionProcessController _processes;

    public CompanionRollbackCoordinator(
        InstallerLayout layout,
        CompanionProcessController processes)
    {
        _layout = layout;
        _processes = processes;
    }

    public IReadOnlyList<Exception> TryRestore(
        InstallerDirectoryTransaction transaction,
        CurrentUserRegistrationSnapshot registrationSnapshot,
        bool restartPreviousAgent)
    {
        var failures = new List<Exception>();
        var processesStopped = TryStep(
            () =>
            {
                using var preparedStop = _processes.PrepareStopInstalledProcesses();
                preparedStop.Execute();
            },
            failures);
        if (!processesStopped)
        {
            return failures;
        }

        var filesRestored = TryStep(
            () => _ = transaction.RollbackFiles(),
            failures);
        var registrationRestored = filesRestored && TryStep(
            registrationSnapshot.Restore,
            failures);
        var agentRestored = registrationRestored;
        if (agentRestored && restartPreviousAgent && File.Exists(_layout.AgentPath))
        {
            agentRestored = TryStep(() => _ = _processes.StartAgent(), failures);
        }
        _ = agentRestored && TryStep(transaction.CompleteRollback, failures);
        return failures;
    }

    private static bool TryStep(Action action, ICollection<Exception> failures)
    {
        try
        {
            action();
            return true;
        }
        catch (Exception exception)
        {
            failures.Add(exception);
            return false;
        }
    }
}
