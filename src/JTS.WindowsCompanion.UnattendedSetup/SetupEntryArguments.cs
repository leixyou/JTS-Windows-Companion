namespace JTS.WindowsCompanion.UnattendedSetup;

internal enum SetupEntryMode { Interactive, Manage, Status, EnrollStandardInput, DelegatedInstallation }

internal static class SetupEntryArguments
{
    internal static SetupEntryMode Parse(string[] arguments) => arguments switch
    {
        [] => SetupEntryMode.Interactive,
        ["--manage"] => SetupEntryMode.Manage,
        ["--status"] => SetupEntryMode.Status,
        ["--enroll-code"] => SetupEntryMode.EnrollStandardInput,
        ["--relay", _, "--delegated-enrollment", _, "--sha256", _, "--export", _] => SetupEntryMode.DelegatedInstallation,
        _ => throw new ArgumentException("SETUP_ARGUMENTS_REJECTED"),
    };
}
