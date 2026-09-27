namespace JTS.WindowsCompanion.UnattendedInstallation;

internal sealed class UnattendedInstallationException(string code) : IOException(code)
{ internal string Code { get; } = code; }

internal enum InstallPhase
{
    Prepared, CreatingAuthority, AuthorityCreated, CreatingWorker, AccountsCreated,
    ConfiguringAccounts, AccountsConfigured, InitializingState, StatePrepared,
    RegisteringServices, ServicesRegistered, Publishing, Published, Activating, Active,
    RollbackStarted, RolledBack, RepairRequired,
}

internal sealed record InstallSnapshot(int SchemaVersion, Guid EnrollmentId, string RelayOrigin, string ReleaseId,
    string ReleaseHash, InstallPhase Phase, LocalAccountIdentity? Authority = null, LocalAccountIdentity? Worker = null, string? DeviceId = null)
{
    internal void Validate()
    {
        if (SchemaVersion != 1 || EnrollmentId == Guid.Empty || !Enum.IsDefined(Phase)
            || ReleaseId is not { Length: > 0 and <= 64 } || !ReleaseId.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-')
            || !Hash(ReleaseHash) || (DeviceId is not null && !Hash(DeviceId))) throw Invalid();
        _ = Origin(RelayOrigin);
        if (Authority is not null) { Authority.Validate(); if (Authority.EnrollmentId != EnrollmentId || Authority.Role != "authority") throw Invalid(); }
        if (Worker is not null) { Worker.Validate(); if (Worker.EnrollmentId != EnrollmentId || Worker.Role != "worker" || Authority is null || Authority.Sid == Worker.Sid) throw Invalid(); }
        if (Phase is >= InstallPhase.AuthorityCreated and <= InstallPhase.Active && Authority is null) throw Invalid();
        if (Phase is >= InstallPhase.AccountsCreated and <= InstallPhase.Active && Worker is null) throw Invalid();
        if (Phase is >= InstallPhase.StatePrepared and <= InstallPhase.Active && DeviceId is null) throw Invalid();
    }
    internal static Uri Origin(string text)
    {
        if (text is not { Length: >= 1 and <= 2048 } || text.Any(c => char.IsControl(c) || c == '\\')
            || !Uri.TryCreate(text, UriKind.Absolute, out var origin) || origin.Scheme != "https"
            || origin.UserInfo.Length != 0 || origin.AbsolutePath != "/" || origin.Query.Length != 0 || origin.Fragment.Length != 0)
            throw new UnattendedInstallationException("INSTALL_RELAY_ORIGIN_REJECTED");
        return origin;
    }
    internal static bool Hash(string? text) => text is { Length: 64 } && text.All(c => "0123456789abcdef".Contains(c));
    private static UnattendedInstallationException Invalid() => new("INSTALL_JOURNAL_INVALID");
}

internal interface IInstallationActions
{
    LocalAccountIdentity CreateAccount(string role);
    void ConfigureAccounts(InstallSnapshot snapshot);
    Task<string> InitializeStateAsync(InstallSnapshot snapshot, CancellationToken stop);
    void RegisterDisabledServices(InstallSnapshot snapshot);
    void Publish(InstallSnapshot snapshot);
    Task ActivateAsync(CancellationToken stop);
    // Must refuse when any helper/process or ownership is uncertain. Never invoked after activation intent.
    Task<bool> RollbackNeverActivatedAsync(InstallSnapshot snapshot);
}
