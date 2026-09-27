namespace JTS.WindowsCompanion.UnattendedSetup;

internal sealed record SetupFailure(string Text, bool MayRetry = false)
{
    // Equality against complete fixed codes is intentional. Never display an arbitrary exception.Message or InnerException.
    internal static SetupFailure From(Exception error) => error.Message switch
    {
        "INSTALL_LOCAL_CONSENT_DECLINED" when error is OperationCanceledException =>
            new("Installation was declined. No installation transaction was started.", MayRetry: true),
        "INSTALL_RELAY_ORIGIN_REJECTED" =>
            new("The relay address was rejected. Use an HTTPS root address without credentials, a path, query or fragment.", MayRetry: true),
        "INSTALL_INTERACTIVE_ELEVATED_ADMIN_REQUIRED" or "INSTALL_ELEVATION_REQUIRED" =>
            new("Setup requires a signed-in administrator and an approved Windows elevation prompt. No automatic retry will occur."),
        "UNATTENDED_INSTALL_WINDOWS_REQUIRED" =>
            new("This setup requires a supported 64-bit Windows installation."),
        "INSTALL_EXISTING_STATE_REQUIRES_LOCAL_REVIEW" or "INSTALL_ALREADY_ATTEMPTED" =>
            new("An existing installation or unresolved attempt needs local review. Setup will not overwrite, adopt or automatically repair it."),
        "INSTALL_ACCOUNT_OWNERSHIP_UNCERTAIN" =>
            new("Account ownership could not be confirmed. Setup preserved the installation record. Local review is required before another attempt."),
        "INSTALL_PROVISIONING_REQUIRES_LOCAL_REPAIR" =>
            new("The initialization process or its profile could not be confirmed closed. Accounts and state were preserved. Local review is required."),
        "INSTALL_ACTIVATION_REQUIRES_LOCAL_REPAIR" =>
            new("Service activation was attempted but installation completion could not be confirmed. Services may be running. State was preserved; local review is required."),
        "INSTALL_ROLLBACK_REQUIRES_LOCAL_REPAIR" =>
            new("Cleanup could not be fully confirmed. Setup preserved the installation record. Local review is required before another attempt."),
        "INSTALL_FAILED_ROLLED_BACK" =>
            new("Installation failed before activation. This attempt's confirmed-owned accounts and service registrations were removed; diagnostic state was retained. Local review is required before trying again."),
        "INSTALL_PAYLOAD_REJECTED" =>
            new("The installation payload was rejected. Use the complete, unmodified release bundle. No automatic retry will occur."),
        _ => new("Installation could not be completed safely. Do not delete installation records or retry blindly: local review is required. No automatic repair was attempted.")
    };
}
