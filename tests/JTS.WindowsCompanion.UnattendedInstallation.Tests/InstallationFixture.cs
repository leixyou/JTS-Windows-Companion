namespace JTS.WindowsCompanion.UnattendedInstallation.Tests;

internal sealed class InstallationFixture : IDisposable, IInstallationActions
{
    internal string Root { get; }
    internal string JournalPath => Path.Combine(Root, "transaction.json");
    internal InstallSnapshot Initial { get; }
    internal InstallJournal Journal { get; }
    internal List<string> Calls { get; } = [];
    internal string? Fail { get; set; }
    internal string FailureCode { get; set; } = "FIXTURE_FAILURE";
    internal bool RollbackConfirmed { get; set; } = true;
    internal Action<string>? OnCall { get; set; }
    internal InstallationFixture()
    {
        var temp = Path.GetTempPath();
        if (OperatingSystem.IsMacOS() && temp.StartsWith("/var/", StringComparison.Ordinal)) temp = "/private" + temp;
        Root = Directory.CreateDirectory(Path.Combine(temp, "jts-install-test-" + Guid.NewGuid().ToString("N"))).FullName;
        Initial = new(1, Guid.NewGuid(), "https://relay.example.invalid/", "2.5.0-test", new string('a', 64), InstallPhase.Prepared);
        Journal = new(JournalPath, Initial);
    }
    internal FirstInstallation Create() => new(Journal, this);
    private void Hit(string name, InstallPhase phase)
    {
        Xunit.Assert.Equal(phase, InstallJournal.Read(JournalPath).Phase); Calls.Add(name); OnCall?.Invoke(name);
        if (Fail == name) throw new UnattendedInstallationException(FailureCode);
    }
    public LocalAccountIdentity CreateAccount(string role)
    {
        Hit(role, role == "authority" ? InstallPhase.CreatingAuthority : InstallPhase.CreatingWorker);
        return Account(role);
    }
    internal LocalAccountIdentity Account(string role) => new(LocalAccountIdentity.AccountName(Initial.EnrollmentId, role),
        "S-1-5-21-1-2-3-" + (role == "authority" ? "1100" : "1101"), Initial.EnrollmentId, role);
    public void ConfigureAccounts(InstallSnapshot snapshot) => Hit("configure", InstallPhase.ConfiguringAccounts);
    public Task<string> InitializeStateAsync(InstallSnapshot snapshot, CancellationToken stop)
    { Hit("initialize", InstallPhase.InitializingState); return Task.FromResult(new string('b', 64)); }
    public void RegisterDisabledServices(InstallSnapshot snapshot) => Hit("register", InstallPhase.RegisteringServices);
    public void Publish(InstallSnapshot snapshot) => Hit("publish", InstallPhase.Publishing);
    public Task ActivateAsync(CancellationToken stop) { Hit("activate", InstallPhase.Activating); return Task.CompletedTask; }
    public Task<bool> RollbackNeverActivatedAsync(InstallSnapshot snapshot)
    { Hit("rollback", InstallPhase.RollbackStarted); return Task.FromResult(RollbackConfirmed); }
    public void Dispose() => Directory.Delete(Root, recursive: true);
}
