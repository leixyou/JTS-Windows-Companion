namespace JTS.WindowsCompanion.UnattendedInstallation;

internal sealed class FirstInstallation(InstallJournal journal, IInstallationActions actions)
{
    private int _used;
    internal async Task<InstallSnapshot> RunAsync(CancellationToken stop)
    {
        if (Interlocked.Exchange(ref _used, 1) != 0 || journal.Current.Phase != InstallPhase.Prepared)
            throw new UnattendedInstallationException("INSTALL_ALREADY_ATTEMPTED");
        try
        {
            Step(InstallPhase.CreatingAuthority, stop);
            var authority = actions.CreateAccount("authority");
            journal.Save(journal.Current with { Phase = InstallPhase.AuthorityCreated, Authority = authority });
            Step(InstallPhase.CreatingWorker, stop);
            var worker = actions.CreateAccount("worker");
            journal.Save(journal.Current with { Phase = InstallPhase.AccountsCreated, Worker = worker });
            Step(InstallPhase.ConfiguringAccounts, stop); actions.ConfigureAccounts(journal.Current);
            Step(InstallPhase.AccountsConfigured, stop);
            Step(InstallPhase.InitializingState, stop);
            var device = await actions.InitializeStateAsync(journal.Current, stop).ConfigureAwait(false);
            journal.Save(journal.Current with { Phase = InstallPhase.StatePrepared, DeviceId = device });
            Step(InstallPhase.RegisteringServices, stop); actions.RegisterDisabledServices(journal.Current);
            Step(InstallPhase.ServicesRegistered, stop);
            Step(InstallPhase.Publishing, stop); actions.Publish(journal.Current);
            Step(InstallPhase.Published, stop);
            // Durable point of no automatic destructive rollback, before any service may execute.
            Step(InstallPhase.Activating, stop);
            await actions.ActivateAsync(stop).ConfigureAwait(false);
            journal.Save(journal.Current with { Phase = InstallPhase.Active });
            return journal.Current;
        }
        catch (Exception error)
        {
            var phase = journal.Current.Phase;
            if (error is UnattendedInstallationException { Code: "PROVISION_PROCESS_STOP_UNCONFIRMED" or "PROVISION_PROFILE_UNLOAD_UNCONFIRMED" })
            { TryRepairRequired(); throw new UnattendedInstallationException("INSTALL_PROVISIONING_REQUIRES_LOCAL_REPAIR"); }
            if (phase >= InstallPhase.Activating)
            {
                TryRepairRequired();
                throw new UnattendedInstallationException("INSTALL_ACTIVATION_REQUIRES_LOCAL_REPAIR");
            }
            // Creating-account phases have no durable SID receipt. Never guess ownership after an ambiguous native call/write.
            if (phase is InstallPhase.CreatingAuthority or InstallPhase.CreatingWorker)
            { TryRepairRequired(); throw new UnattendedInstallationException("INSTALL_ACCOUNT_OWNERSHIP_UNCERTAIN"); }
            try
            {
                journal.Save(journal.Current with { Phase = InstallPhase.RollbackStarted });
                if (!await actions.RollbackNeverActivatedAsync(journal.Current).ConfigureAwait(false))
                    throw new UnattendedInstallationException("INSTALL_ROLLBACK_UNCONFIRMED");
                journal.Save(journal.Current with { Phase = InstallPhase.RolledBack });
            }
            catch { TryRepairRequired(); throw new UnattendedInstallationException("INSTALL_ROLLBACK_REQUIRES_LOCAL_REPAIR"); }
            throw new UnattendedInstallationException("INSTALL_FAILED_ROLLED_BACK");
        }
    }
    private void Step(InstallPhase phase, CancellationToken stop)
    { stop.ThrowIfCancellationRequested(); journal.Save(journal.Current with { Phase = phase }); }
    private void TryRepairRequired()
    { try { journal.Save(journal.Current with { Phase = InstallPhase.RepairRequired }); } catch { /* Original durable phase remains unresolved, never silently reset. */ } }
}
