namespace JTS.WindowsCompanion.UnattendedSetup;

internal static class SetupText
{
    internal const string Title = "JTS Terminal 2.5 — Optional unattended setup";
    internal const string Changes = "This first installation creates two dedicated standard Windows accounts. "
        + "The Authority network service starts automatically; the separate script Worker starts only on demand.\r\n\r\n"
        + "Device pairing and capability permissions are approved separately. Installing does not authorize a remote device or MCP client. "
        + "Scripts use the Worker's actual account permissions; a working folder is not a script sandbox.\r\n\r\n"
        + "Your existing JTS Terminal 2.0 Companion is not replaced. This setup does not upgrade, repair or uninstall an existing 2.5 installation.";
    internal const string OriginHelp = "Enter the HTTPS root address of the relay you intend to use. Do not include a path, credentials, query or fragment. "
        + "The service requires a certificate trusted by Windows; entering an IP address does not bypass certificate validation.";
    internal const string Ready = "Review the changes, enter your relay address, then select Install. A separate confirmation defaults to No.";
    internal const string Busy = "Installation is in progress. Keep this window open. Setup will finish or preserve unresolved state for local review; "
        + "closing this window will not interrupt the transaction.";
    internal const string Success = "Local installation completed and Windows reported the Authority service running. "
        + "This does not confirm relay connectivity, device pairing, remote permissions or end-to-end operation. "
        + "The public identifiers below are for matching this device during later pairing.";
}
