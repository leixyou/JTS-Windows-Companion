namespace JTS.WindowsCompanion.Setup;

internal enum InstallerAction
{
    Install,
    InstallInternal,
    Repair,
    Uninstall,
    UninstallInternal,
    RevokeDelegation,
}

internal sealed record InstallerOptions(
    InstallerAction Action,
    bool Quiet,
    bool PurgeData,
    string? DelegatedEnrollmentPath = null,
    string? DelegatedEnrollmentSha256 = null,
    Guid? RevokeDelegationGrantId = null)
{
    public static InstallerOptions Parse(string[] arguments)
    {
        var action = InstallerAction.Install;
        var actionWasSet = false;
        var quiet = false;
        var purgeData = false;
        string? enrollmentPath = null;
        string? enrollmentSha256 = null;
        Guid? revokeGrantId = null;
        for (var index = 0; index < arguments.Length; index++)
        {
            var argument = arguments[index];
            switch (argument)
            {
                case "--install":
                    SetAction(InstallerAction.Install);
                    break;
                case "--install-internal":
                    SetAction(InstallerAction.InstallInternal);
                    break;
                case "--repair":
                    SetAction(InstallerAction.Repair);
                    break;
                case "--uninstall":
                    SetAction(InstallerAction.Uninstall);
                    break;
                case "--uninstall-internal":
                    SetAction(InstallerAction.UninstallInternal);
                    break;
                case "--delegated-enrollment":
                    if (enrollmentPath is not null) throw new ArgumentException("Duplicate enrollment path.");
                    enrollmentPath = Path.GetFullPath(ReadValue());
                    break;
                case "--delegated-enrollment-sha256":
                    if (enrollmentSha256 is not null) throw new ArgumentException("Duplicate enrollment checksum.");
                    enrollmentSha256 = ReadValue();
                    if (enrollmentSha256.Length != 64 || !enrollmentSha256.All(Uri.IsHexDigit))
                        throw new ArgumentException("The enrollment checksum is invalid.");
                    break;
                case "--revoke-delegation":
                    SetAction(InstallerAction.RevokeDelegation);
                    if (revokeGrantId is not null || !Guid.TryParseExact(ReadValue(), "D", out var id) || id == Guid.Empty)
                        throw new ArgumentException("The delegation grant ID is invalid.");
                    revokeGrantId = id;
                    break;
                case "--quiet":
                    quiet = true;
                    break;
                case "--purge-data":
                    purgeData = true;
                    break;
                default:
                    throw new ArgumentException("The setup command line is invalid.");
            }

            string ReadValue()
            {
                if (++index >= arguments.Length || string.IsNullOrWhiteSpace(arguments[index]))
                    throw new ArgumentException("The setup option requires a value.");
                return arguments[index];
            }
        }

        if ((enrollmentPath is null) != (enrollmentSha256 is null) ||
            (enrollmentPath is not null && action is not (InstallerAction.Install or InstallerAction.InstallInternal or InstallerAction.Repair)))
            throw new ArgumentException("Delegated enrollment requires its pinned checksum and an install action.");

        if (purgeData && action is not InstallerAction.Uninstall and not InstallerAction.UninstallInternal)
        {
            throw new ArgumentException("--purge-data is valid only during uninstall.");
        }

        return new InstallerOptions(action, quiet, purgeData, enrollmentPath, enrollmentSha256, revokeGrantId);

        void SetAction(InstallerAction value)
        {
            if (actionWasSet && action != value)
            {
                throw new ArgumentException("Only one setup action can be requested.");
            }

            action = value;
            actionWasSet = true;
        }
    }
}
