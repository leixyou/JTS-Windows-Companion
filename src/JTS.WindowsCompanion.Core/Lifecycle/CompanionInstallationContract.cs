namespace JTS.WindowsCompanion.Lifecycle;

public static class CompanionInstallationContract
{
    public const string AgentFileName = "JTS.WindowsCompanion.Agent.exe";
    public const string BrokerFileName = "JTS.WindowsCompanion.UacBroker.exe";
    public const string SetupFileName = "JTS.WindowsCompanion.Setup.exe";
    public const string OperationLockFileName = ".jts-windows-companion-setup.lock";

    public static string InstallRoot(string localApplicationData) =>
        Path.Combine(
            Path.GetFullPath(localApplicationData),
            "Programs",
            "JTS Terminal",
            "Windows Companion");
}
