using JTS.WindowsCompanion.UnattendedInstallation;

namespace JTS.WindowsCompanion.UnattendedSetup;

internal sealed partial class SetupForm : Form
{
    private readonly string _bundleDirectory;
    private readonly TextBox _relay = new() { MaxLength = 2048, Dock = DockStyle.Fill, AccessibleName = "Relay HTTPS root address" };
    private readonly CheckBox _acknowledgment = new()
    { Text = "I have reviewed these optional changes and want to install unattended support.", AutoSize = true, Dock = DockStyle.Fill };
    private readonly Button _install = new() { Text = "Install…", AutoSize = true, Enabled = false, MinimumSize = new Size(112, 36) };
    private readonly Button _close = new() { Text = "Close", AutoSize = true, MinimumSize = new Size(112, 36) };
    private readonly Label _status = new() { AutoSize = true, Dock = DockStyle.Fill, Text = SetupText.Ready, AccessibleName = "Installation status" };
    private readonly TextBox _identifiers = new()
    { ReadOnly = true, Multiline = true, Dock = DockStyle.Fill, ScrollBars = ScrollBars.Vertical, Visible = false, AccessibleName = "Public installation identifiers" };
    private readonly ProgressBar _progress = new() { Dock = DockStyle.Fill, Style = ProgressBarStyle.Marquee, MarqueeAnimationSpeed = 0, Visible = false };
    private bool _busy;
    private bool _finished;
    internal int ExitCode { get; private set; }

    internal SetupForm(string bundleDirectory)
    {
        _bundleDirectory = bundleDirectory;
        InitializeLayout();
        _relay.TextChanged += (_, _) => UpdateInstallAvailability();
        _acknowledgment.CheckedChanged += (_, _) => UpdateInstallAvailability();
        _install.Click += async (_, _) => await InstallAsync();
        _close.Click += (_, _) => Close();
        FormClosing += (_, args) => { if (_busy) args.Cancel = true; };
        Shown += (_, _) => _relay.Focus();
        // Do not assign Install as the default Enter-key action.
        CancelButton = _close;
    }

    private void UpdateInstallAvailability() => _install.Enabled = !_busy && !_finished
        && _acknowledgment.Checked && RelayOriginInput.TryNormalize(_relay.Text, out _);

    private async Task InstallAsync()
    {
        if (_busy || _finished || !_acknowledgment.Checked || !RelayOriginInput.TryNormalize(_relay.Text, out var origin)) return;
        SetBusy(true);
        _status.Text = SetupText.Busy;
        try
        {
            // Run the synchronous pre-await native launch on this UI thread. Task.Run would allow UI-window
            // creation to race the launcher's brief process-wide window-station switch. No DoEvents is used.
            var installed = await WindowsUnattendedInstaller.InstallWithConsentAsync(_bundleDirectory, origin);
            _finished = true;
            ExitCode = 0;
            _status.Text = SetupText.Success;
            _identifiers.Text = $"Device ID: {installed.DeviceId}\r\nEnrollment ID: {installed.EnrollmentId:D}";
            _identifiers.Visible = true;
        }
        catch (Exception error)
        {
            var failure = SetupFailure.From(error);
            _finished = !failure.MayRetry;
            ExitCode = failure.MayRetry ? 0 : 1;
            _status.Text = failure.Text;
        }
        finally
        {
            SetBusy(false);
            _close.Focus();
        }
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        _relay.Enabled = !busy && !_finished;
        _acknowledgment.Enabled = !busy && !_finished;
        _close.Enabled = !busy;
        ControlBox = !busy;
        _progress.Visible = busy;
        _progress.MarqueeAnimationSpeed = busy ? 30 : 0;
        UpdateInstallAvailability();
    }
}
