namespace JTS.WindowsCompanion.UnattendedSetup;

internal sealed partial class SetupForm
{
    private void InitializeLayout()
    {
        Text = SetupText.Title;
        StartPosition = FormStartPosition.CenterScreen;
        AutoScaleMode = AutoScaleMode.Dpi; AutoScaleDimensions = new SizeF(96, 96);
        ClientSize = new Size(780, 760); MinimumSize = new Size(700, 690); MaximizeBox = false;
        var layout = new TableLayoutPanel
        { Dock = DockStyle.Fill, Padding = new Padding(24), ColumnCount = 1, RowCount = 12, AutoScroll = true };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (var i = 0; i < 9; i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 68));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        Controls.Add(layout);
        var heading = Label("Connect this Windows computer", 14);
        heading.Font = new Font(Font.FontFamily, 17, FontStyle.Bold);
        layout.Controls.Add(heading, 0, 0);
        layout.Controls.Add(Label(SetupText.Changes, 16), 0, 1);
        layout.Controls.Add(Label("One-use connection code", 6), 0, 2);
        _code.Margin = new Padding(0, 0, 0, 12);
        layout.Controls.Add(_code, 0, 3);
        _optionalInstallation = OptionalInstallation();
        layout.Controls.Add(_optionalInstallation, 0, 4);
        _progress.Margin = new Padding(0, 0, 0, 10); _progress.Height = 8;
        layout.Controls.Add(_progress, 0, 5);
        _status.Margin = new Padding(0, 0, 0, 6);
        _status.Font = new Font(Font, FontStyle.Bold);
        layout.Controls.Add(_status, 0, 6);
        _detail.Margin = new Padding(0, 0, 0, 14);
        layout.Controls.Add(_detail, 0, 7);
        layout.Controls.Add(Label(EnrollmentPresentation.RdpStatus, 12), 0, 8);
        _identifiers.Margin = new Padding(0, 0, 0, 12);
        layout.Controls.Add(_identifiers, 0, 10);
        var buttons = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 4, RowCount = 1, AutoSize = true, Margin = Padding.Empty };
        buttons.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        buttons.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        buttons.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        _revoke.Margin = Padding.Empty; _connect.Margin = new Padding(0, 0, 10, 0); _close.Margin = Padding.Empty;
        buttons.Controls.Add(_revoke, 0, 0); buttons.Controls.Add(_connect, 2, 0); buttons.Controls.Add(_close, 3, 0);
        layout.Controls.Add(buttons, 0, 11);
    }

    private System.Windows.Forms.Control OptionalInstallation()
    {
        var panel = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 3, AutoSize = true, Margin = new Padding(0, 0, 0, 16) };
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var help = Label(SetupText.OriginHelp, 8);
        panel.Controls.Add(help, 0, 0); panel.SetColumnSpan(help, 2);
        _relay.Margin = new Padding(0, 6, 12, 0); _install.Margin = Padding.Empty;
        panel.Controls.Add(_relay, 0, 1); panel.Controls.Add(_install, 1, 1);
        return panel;
    }

    private static Label Label(string text, int bottom) => new()
    { Text = text, Dock = DockStyle.Fill, AutoSize = true, Margin = new Padding(0, 0, 0, bottom) };
}
