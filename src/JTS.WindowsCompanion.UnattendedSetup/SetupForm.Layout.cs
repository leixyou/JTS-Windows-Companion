namespace JTS.WindowsCompanion.UnattendedSetup;

internal sealed partial class SetupForm
{
    private void InitializeLayout()
    {
        Text = SetupText.Title;
        StartPosition = FormStartPosition.CenterScreen;
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoScaleDimensions = new SizeF(96, 96);
        ClientSize = new Size(780, 700);
        MinimumSize = new Size(700, 650);
        MaximizeBox = false;

        var layout = new TableLayoutPanel
        { Dock = DockStyle.Fill, Padding = new Padding(24), ColumnCount = 1, RowCount = 11, AutoScroll = true };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (var i = 0; i < 8; i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 88));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        Controls.Add(layout);

        var heading = Label("Install unattended support", bottom: 14);
        heading.Font = new Font(Font.FontFamily, 17, FontStyle.Bold);
        layout.Controls.Add(heading, 0, 0);
        layout.Controls.Add(Label(SetupText.Changes, bottom: 18), 0, 1);
        layout.Controls.Add(Label("Relay HTTPS root address", bottom: 6), 0, 2);
        _relay.Margin = new Padding(0, 0, 0, 8);
        layout.Controls.Add(_relay, 0, 3);
        layout.Controls.Add(Label(SetupText.OriginHelp, bottom: 18), 0, 4);
        _acknowledgment.Margin = new Padding(0, 0, 0, 18);
        layout.Controls.Add(_acknowledgment, 0, 5);
        _progress.Margin = new Padding(0, 0, 0, 10);
        _progress.Height = 10;
        layout.Controls.Add(_progress, 0, 6);
        _status.Margin = new Padding(0, 0, 0, 12);
        layout.Controls.Add(_status, 0, 7);
        _identifiers.Margin = new Padding(0, 0, 0, 12);
        layout.Controls.Add(_identifiers, 0, 9);

        var buttons = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1, AutoSize = true, Margin = Padding.Empty };
        buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        buttons.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        buttons.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        _install.Margin = new Padding(0, 0, 10, 0);
        _close.Margin = Padding.Empty;
        buttons.Controls.Add(_install, 1, 0);
        buttons.Controls.Add(_close, 2, 0);
        layout.Controls.Add(buttons, 0, 10);
    }

    private static Label Label(string text, int bottom) => new()
    { Text = text, Dock = DockStyle.Fill, AutoSize = true, Margin = new Padding(0, 0, 0, bottom) };
}
