using System.Reflection;
using Microsoft.Win32;

namespace JTS.WindowsCompanion.Setup;

internal sealed class CurrentUserRegistrationManager
{
    private readonly InstallerLayout _layout;
    private readonly CompanionProcessController _processes;

    public CurrentUserRegistrationManager(
        InstallerLayout layout,
        CompanionProcessController processes)
    {
        _layout = layout;
        _processes = processes;
    }

    public void Write()
    {
        using (var runKey = Registry.CurrentUser.CreateSubKey(
                   CurrentUserRegistrationSnapshot.RunKeyPath,
                   writable: true)
               ?? throw new UnauthorizedAccessException("The current-user startup registry key is unavailable."))
        {
            runKey.SetValue(
                CurrentUserRegistrationSnapshot.StartupValueName,
                _processes.AgentCommandLine(),
                RegistryValueKind.String);
        }

        Registry.CurrentUser.DeleteSubKeyTree(
            CurrentUserRegistrationSnapshot.UninstallKeyPath,
            throwOnMissingSubKey: false);
        using var uninstallKey = Registry.CurrentUser.CreateSubKey(
                CurrentUserRegistrationSnapshot.UninstallKeyPath,
                writable: true)
            ?? throw new UnauthorizedAccessException("The current-user uninstall registry key is unavailable.");
        var version = Assembly.GetExecutingAssembly().GetName().Version ?? new Version(2, 0, 0);
        uninstallKey.SetValue("DisplayName", "JTS Windows Companion", RegistryValueKind.String);
        uninstallKey.SetValue("DisplayVersion", $"{version.Major}.{version.Minor}.{version.Build}", RegistryValueKind.String);
        uninstallKey.SetValue("Publisher", "JTS Tools", RegistryValueKind.String);
        uninstallKey.SetValue("InstallLocation", _layout.InstallRoot, RegistryValueKind.String);
        uninstallKey.SetValue("DisplayIcon", _layout.SetupPath, RegistryValueKind.String);
        uninstallKey.SetValue("UninstallString", $"{Quote(_layout.SetupPath)} --uninstall", RegistryValueKind.String);
        uninstallKey.SetValue("QuietUninstallString", $"{Quote(_layout.SetupPath)} --uninstall --quiet", RegistryValueKind.String);
        uninstallKey.SetValue("ModifyPath", $"{Quote(_layout.SetupPath)} --repair", RegistryValueKind.String);
        uninstallKey.SetValue("NoModify", 0, RegistryValueKind.DWord);
        uninstallKey.SetValue("NoRepair", 0, RegistryValueKind.DWord);
        uninstallKey.SetValue("InstallDate", DateTime.UtcNow.ToString("yyyyMMdd"), RegistryValueKind.String);
        uninstallKey.SetValue("EstimatedSize", EstimatedSizeKilobytes(), RegistryValueKind.DWord);
    }

    public static void Remove()
    {
        using (var runKey = Registry.CurrentUser.OpenSubKey(
                   CurrentUserRegistrationSnapshot.RunKeyPath,
                   writable: true))
        {
            runKey?.DeleteValue(
                CurrentUserRegistrationSnapshot.StartupValueName,
                throwOnMissingValue: false);
        }
        Registry.CurrentUser.DeleteSubKeyTree(
            CurrentUserRegistrationSnapshot.UninstallKeyPath,
            throwOnMissingSubKey: false);
    }

    private int EstimatedSizeKilobytes()
    {
        var bytes = new[] { _layout.AgentPath, _layout.BrokerPath, _layout.SetupPath }
            .Where(File.Exists)
            .Sum(path => new FileInfo(path).Length);
        return checked((int)Math.Min(int.MaxValue, Math.Max(1, (bytes + 1_023) / 1_024)));
    }

    private static string Quote(string value) =>
        WindowsCommandLineArgumentQuoter.Quote(value);
}
