using JTS.WindowsCompanion.Enrollment;
using JTS.WindowsCompanion.UnattendedInstallation;

namespace JTS.WindowsCompanion.UnattendedSetup;

internal sealed partial class SetupForm : Form
{
    private readonly string _bundleDirectory;
    private readonly CancellationTokenSource _closed = new();
    private readonly System.Windows.Forms.Timer _poll = new() { Interval = 2000 };
    private readonly TextBox _code = new() { MaxLength = EnrollmentCodeInput.MaximumCharacters, UseSystemPasswordChar = true, Dock = DockStyle.Fill, AccessibleName = "One-use connection code" };
    private readonly TextBox _relay = new() { MaxLength = 2048, Dock = DockStyle.Fill, AccessibleName = "Relay HTTPS root address" };
    private readonly Button _connect = new() { Text = "Connect", AutoSize = true, MinimumSize = new Size(112, 36) };
    private readonly Button _install = new() { Text = "Install without pairing", AutoSize = true, MinimumSize = new Size(160, 36) };
    private readonly Button _revoke = new() { Text = "Revoke access", AutoSize = true, MinimumSize = new Size(112, 36) };
    private readonly Button _close = new() { Text = "Close", AutoSize = true, MinimumSize = new Size(112, 36) };
    private readonly Label _status = new() { AutoSize = true, Dock = DockStyle.Fill, AccessibleName = "Pairing status" };
    private readonly Label _detail = new() { AutoSize = true, Dock = DockStyle.Fill };
    private readonly TextBox _identifiers = new() { ReadOnly = true, Multiline = true, Dock = DockStyle.Fill, ScrollBars = ScrollBars.Vertical, AccessibleName = "Public device identifiers" };
    private readonly ProgressBar _progress = new() { Dock = DockStyle.Fill, Style = ProgressBarStyle.Marquee, MarqueeAnimationSpeed = 0, Visible = false };
    private System.Windows.Forms.Control _optionalInstallation = null!;
    private CompanionInstallationPresence _presence;
    private EnrollmentManagementStatus? _lastStatus;
    private bool _busy, _backgroundPoll, _installing, _disposed;
    internal int ExitCode { get; private set; }

    internal SetupForm(string bundleDirectory, CompanionInstallationPresence presence)
    {
        _bundleDirectory = bundleDirectory; _presence = presence;
        InitializeLayout();
        _status.Text = presence == CompanionInstallationPresence.Absent ? SetupText.Ready : "Reading pairing status…";
        if (presence == CompanionInstallationPresence.NeedsReview) _status.Text = SetupText.Review;
        _code.TextChanged += (_, _) => UpdateAvailability();
        _relay.TextChanged += (_, _) => UpdateAvailability();
        _connect.Click += async (_, _) => await ConnectAsync();
        _install.Click += async (_, _) => await InstallOnlyAsync();
        _revoke.Click += async (_, _) => await RevokeAsync();
        _close.Click += (_, _) => Close();
        _poll.Tick += async (_, _) => await RefreshStatusAsync();
        FormClosing += (_, args) => { if (_installing) args.Cancel = true; else _closed.Cancel(); };
        Shown += async (_, _) => { _code.Focus(); _poll.Start(); await RefreshStatusAsync(); };
        CancelButton = _close;
        UpdateAvailability();
    }

    private async Task ConnectAsync()
    {
        if (!_connect.Enabled) return;
        SetBusy(true);
        try
        {
            var code = _code.Text.Trim();
            ApplyStatus(await EnrollmentEntryWorkflow.EnrollAsync(code, _presence, InstallAsync,
                WindowsEnrollmentManagementClient.EnrollAsync, _closed.Token));
            if (!IsDisposed) _code.Clear();
        }
        catch (Exception error) { ShowFailure(error); }
        finally { if (!IsDisposed) SetBusy(false); }
    }

    private async Task InstallOnlyAsync()
    {
        if (!_install.Enabled || !RelayOriginInput.TryNormalize(_relay.Text, out var origin)) return;
        SetBusy(true);
        try { await InstallAsync(origin); await ReadStatusAsync(); }
        catch (Exception error) { ShowFailure(error); }
        finally { if (!IsDisposed) SetBusy(false); }
    }

    private async Task InstallAsync(string origin)
    {
        _installing = true; _close.Enabled = false; ControlBox = false; _status.Text = SetupText.Busy;
        try
        {
            // Keep the native pre-await launch on the UI thread. Closing must not interrupt an installation transaction.
            var installed = await WindowsUnattendedInstaller.InstallWithConsentAsync(_bundleDirectory, origin);
            _presence = CompanionInstallationPresence.Installed;
            _identifiers.Text = $"Device ID: {installed.DeviceId}\r\nRelay: {installed.RelayOrigin}";
            _status.Text = "Installed. Reading pairing status…";
        }
        catch { _presence = CompanionInstallationPresence.NeedsReview; ExitCode = 1; throw; }
        finally { _installing = false; _close.Enabled = true; ControlBox = true; }
    }

    private async Task RevokeAsync()
    {
        if (!_revoke.Enabled || _lastStatus?.InvitationId is not Guid invitation) return;
        SetBusy(true);
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(_closed.Token);
            deadline.CancelAfter(TimeSpan.FromSeconds(30));
            ApplyStatus(await WindowsEnrollmentManagementClient.RevokeAsync(invitation, deadline.Token));
        }
        catch (Exception error) { ShowFailure(error); }
        finally { if (!IsDisposed) SetBusy(false); }
    }

    private async Task RefreshStatusAsync()
    {
        if (_busy || _presence != CompanionInstallationPresence.Installed || _closed.IsCancellationRequested) return;
        SetBusy(true, backgroundPoll: true);
        try { await ReadStatusAsync(); }
        catch (Exception error) { ShowFailure(error); }
        finally { if (!IsDisposed) SetBusy(false); }
    }

    private async Task ReadStatusAsync()
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(_closed.Token);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        ApplyStatus(await WindowsEnrollmentManagementClient.StatusAsync(deadline.Token));
    }

    private void ApplyStatus(EnrollmentManagementStatus status)
    {
        if (_closed.IsCancellationRequested) return;
        _lastStatus = status;
        var text = EnrollmentPresentation.From(status.State, status.InvitationId.HasValue);
        _status.Text = text.Pairing; _detail.Text = text.Detail;
        _identifiers.Text = $"Device ID: {status.DeviceId}\r\nRelay: {status.RelayOrigin}";
        if (status.ErrorCode is not null) _detail.Text += "\r\n" + EnrollmentFailure.FromCode(status.ErrorCode);
        _revoke.Text = status.State == "bound" ? "Revoke access" : "Cancel pairing";
    }

    private void ShowFailure(Exception error)
    {
        if (_closed.IsCancellationRequested) return;
        _detail.Text = error is EnrollmentException enrollment ? EnrollmentFailure.FromCode(enrollment.Code)
            : error is OperationCanceledException ? "The service did not respond in time. Its saved pairing state is preserved; status will be checked again."
            : SetupFailure.From(error).Text;
    }

    private void SetBusy(bool busy, bool backgroundPoll = false)
    {
        _busy = busy; _backgroundPoll = busy && backgroundPoll;
        _progress.Visible = busy && !backgroundPoll; _progress.MarqueeAnimationSpeed = busy && !backgroundPoll ? 30 : 0;
        UpdateAvailability();
    }

    private void UpdateAvailability()
    {
        var absent = _presence == CompanionInstallationPresence.Absent;
        var presentation = EnrollmentPresentation.From(_lastStatus?.State ?? "unavailable", _lastStatus?.InvitationId is not null);
        var maySubmit = absent || _presence == CompanionInstallationPresence.Installed && presentation.MaySubmit;
        _code.Enabled = (!_busy || _backgroundPoll) && maySubmit;
        _connect.Enabled = !_busy && maySubmit && !string.IsNullOrWhiteSpace(_code.Text);
        _optionalInstallation.Visible = absent; _relay.Enabled = !_busy;
        _install.Enabled = !_busy && absent && RelayOriginInput.TryNormalize(_relay.Text, out _);
        _revoke.Enabled = !_busy && _presence == CompanionInstallationPresence.Installed && presentation.MayRevoke;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _disposed = true; _poll.Stop(); _poll.Dispose(); _closed.Cancel(); _closed.Dispose();
        }
        base.Dispose(disposing);
    }
}
