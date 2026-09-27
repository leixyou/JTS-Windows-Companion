namespace JTS.WindowsCompanion.UnattendedSetup;

internal static class SetupText
{
    internal const string Title = "JTS Terminal — Windows connection";
    internal const string Changes = "Paste the one-use connection code from your Mac. On a new computer, Connect installs "
        + "the Authority service and a separate standard-account script Worker, then binds this device. "
        + "On an installed computer, it opens the existing connection. The Mac's AI-control permission includes delegated pairing.\r\n\r\n"
        + "Traffic remains encrypted through the relay. Outer HTTPS certificate checks are skipped by default; "
        + "device identity checks remain required. Scripts use the Worker's account permissions; the shared folder is not a script sandbox.";
    internal const string OriginHelp = "Optional: install before obtaining a code. Enter only the relay's HTTPS root address. "
        + "You can return to this window to paste a code later.";
    internal const string Ready = "Paste a connection code to install and pair. No Windows desktop login is required for pairing.";
    internal const string Busy = "Installing local services. Keep this window open until the installation transaction finishes.";
    internal const string Review = "An incomplete or inconsistent installation needs local review. Setup will not overwrite its services or records.";
}
