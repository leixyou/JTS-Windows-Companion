using System.Runtime.Versioning;

namespace JTS.WindowsCompanion.UnattendedInstallation;

[SupportedOSPlatform("windows")]
internal sealed class WindowsInstallationActions(Guid enrollment, WindowsInstallationStorage storage, InstallationPayload payload, byte[]? delegation = null)
    : IInstallationActions, IDisposable
{
    private readonly WindowsLocalAccountManager _accounts = new();
    private readonly WindowsInstalledServices _services = new();
    private readonly AccountPassword _authorityPassword = AccountPassword.Create(), _workerPassword = AccountPassword.Create();
    private LocalAccountIdentity? _authority, _worker;
    private bool _helperUncertain;
    private DateTimeOffset _started;
    private PreparedAuthorityState? _prepared;
    internal string? PublicKeySpkiBase64 => _prepared?.PublicKeySpkiBase64;
    public LocalAccountIdentity CreateAccount(string role)
    {
        var account = _accounts.CreateDisabled(LocalAccountIdentity.AccountName(enrollment, role), role, enrollment,
            role == "authority" ? _authorityPassword : _workerPassword);
        if (role == "authority") _authority = account; else _worker = account;
        return account;
    }
    public void ConfigureAccounts(InstallSnapshot snapshot)
    {
        Match(snapshot);
        _accounts.ConfigureServiceLogon(_authority!); _accounts.ConfigureServiceLogon(_worker!);
        _accounts.Enable(_authority!); _accounts.Enable(_worker!);
    }
    public async Task<string> InitializeStateAsync(InstallSnapshot snapshot, CancellationToken stop)
    {
        Match(snapshot); _started = DateTimeOffset.UtcNow;
        storage.PrepareStage(snapshot, payload, _started, delegation);
        _helperUncertain = true;
        try
        {
            await WindowsProvisioningLauncher.RunAsync(_authority!, _authorityPassword,
                Path.Combine(storage.ProgramDirectory, "JTS.WindowsCompanion.AuthorityProvisioner.exe"), stop).ConfigureAwait(false);
            _helperUncertain = false;
        }
        catch (UnattendedInstallationException error) when (error.Code is not ("PROVISION_PROCESS_STOP_UNCONFIRMED" or "PROVISION_PROFILE_UNLOAD_UNCONFIRMED"))
        { _helperUncertain = false; throw; }
        // Cancellation/unknown exception has no successful-drain assertion. Preserve state conservatively.
        _prepared = PreparedStateVerifier.Verify(storage.State, snapshot, _started, DateTimeOffset.UtcNow);
        return _prepared.DeviceId;
    }
    public void RegisterDisabledServices(InstallSnapshot snapshot)
    {
        Match(snapshot);
        _services.RegisterDisabled(_authority!, _authorityPassword, _worker!, _workerPassword, storage.ProgramDirectory, enrollment);
    }
    public void Publish(InstallSnapshot snapshot)
    {
        Match(snapshot);
        var state = PreparedStateVerifier.Verify(storage.State, snapshot, _started, DateTimeOffset.UtcNow);
        if (_prepared is null || state != _prepared || snapshot.DeviceId != state.DeviceId)
            throw new UnattendedInstallationException("INSTALL_STAGE_CHANGED");
        _accounts.VerifyOwned(_authority!); _accounts.VerifyOwned(_worker!);
        storage.Publish(snapshot);
    }
    public Task ActivateAsync(CancellationToken stop) => _services.ActivateAsync(stop);
    public Task<bool> RollbackNeverActivatedAsync(InstallSnapshot snapshot)
    {
        if (_helperUncertain || _services.ActivationAttempted) return Task.FromResult(false);
        // Only exact in-process receipts and original service handles are eligible, never names from an untrusted recovery guess.
        if (snapshot.Authority != _authority || snapshot.Worker != _worker) return Task.FromResult(false);
        try
        {
            _services.RollbackNeverActivated();
            storage.RetainFailedFiles();
            if (_worker is not null) _accounts.DeleteOwned(_worker);
            if (_authority is not null) _accounts.DeleteOwned(_authority);
            return Task.FromResult(true);
        }
        catch { return Task.FromResult(false); }
    }
    private void Match(InstallSnapshot snapshot)
    {
        if (snapshot.EnrollmentId != enrollment || _authority is null || _worker is null
            || snapshot.Authority != _authority || snapshot.Worker != _worker) throw new UnattendedInstallationException("INSTALL_ACCOUNT_RECEIPT_MISMATCH");
    }
    public void Dispose() { _services.Dispose(); _workerPassword.Dispose(); _authorityPassword.Dispose(); }
}
