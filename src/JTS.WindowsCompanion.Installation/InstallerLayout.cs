using System.Reflection;
using JTS.WindowsCompanion.Lifecycle;
using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.Setup;

internal sealed class InstallerLayout
{
    public const string AgentFileName = CompanionInstallationContract.AgentFileName;
    public const string BrokerFileName = CompanionInstallationContract.BrokerFileName;
    public const string SetupFileName = CompanionInstallationContract.SetupFileName;
    public const string AgentResourceName = "JTS.Setup.Payload.Agent.exe";
    public const string BrokerResourceName = "JTS.Setup.Payload.UacBroker.exe";
    public const string ReleaseManifestResourceName = "JTS.Setup.Payload.ReleaseManifest.json";

    public InstallerLayout()
    {
        var localApplicationData = Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData,
            Environment.SpecialFolderOption.Create);
        if (string.IsNullOrWhiteSpace(localApplicationData))
        {
            throw new InvalidOperationException("The current user's Local Application Data directory is unavailable.");
        }

        LocalApplicationData = Path.GetFullPath(localApplicationData);
        InstallRoot = CompanionInstallationContract.InstallRoot(LocalApplicationData);
        InstallParent = Directory.GetParent(InstallRoot)?.FullName
            ?? throw new InvalidOperationException("The installation directory has no parent.");
        TransactionJournalPath = Path.Combine(
            InstallParent,
            ".jts-windows-companion-setup-transaction.json");
        OperationLockPath = Path.Combine(
            InstallParent,
            CompanionInstallationContract.OperationLockFileName);
        StateRoot = Path.Combine(
            LocalApplicationData,
            "JTSTerminal",
            "WindowsCompanion");
        AgentPath = Path.Combine(InstallRoot, AgentFileName);
        BrokerPath = Path.Combine(InstallRoot, BrokerFileName);
        SetupPath = Path.Combine(InstallRoot, SetupFileName);
        ReleaseManifestPath = Path.Combine(InstallRoot, ReleaseManifestTrust.ManifestFileName);
    }

    public string LocalApplicationData { get; }

    public string InstallRoot { get; }

    public string InstallParent { get; }

    public string TransactionJournalPath { get; }

    public string OperationLockPath { get; }

    public string StateRoot { get; }

    public string AgentPath { get; }

    public string BrokerPath { get; }

    public string SetupPath { get; }

    public string ReleaseManifestPath { get; }

    public string CreateStagingRoot()
    {
        Directory.CreateDirectory(InstallParent);
        EnsureSafeInstallRoot(LocalApplicationData, InstallParent);
        var staging = Path.Combine(InstallParent, $".setup-{Guid.NewGuid():N}");
        Directory.CreateDirectory(staging);
        RejectReparsePoint(staging);
        return staging;
    }

    public static async Task ExtractResourceAsync(
        Assembly assembly,
        string resourceName,
        string destination,
        CancellationToken cancellationToken)
    {
        await using var input = assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidDataException($"The setup payload {resourceName} is missing.");
        await using var output = new FileStream(
            destination,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            128 * 1024,
            FileOptions.Asynchronous | FileOptions.WriteThrough);
        await input.CopyToAsync(output, cancellationToken).ConfigureAwait(false);
        await output.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public static void EnsureSafeInstallRoot(string localApplicationData, string installRoot)
    {
        var localRoot = Path.GetFullPath(localApplicationData)
            .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var candidate = Path.GetFullPath(installRoot);
        if (!candidate.StartsWith(localRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException("The installation path escapes Local Application Data.");
        }

        var current = new DirectoryInfo(candidate);
        while (current is not null && current.FullName.StartsWith(localRoot, StringComparison.OrdinalIgnoreCase))
        {
            if (current.Exists)
            {
                RejectReparsePoint(current.FullName);
            }
            current = current.Parent;
        }
    }

    public static void DeleteDirectoryWithoutFollowingLinks(string path)
    {
        if (!Directory.Exists(path))
        {
            return;
        }
        RejectReparsePoint(path);
        foreach (var entry in Directory.EnumerateFileSystemEntries(path))
        {
            var attributes = File.GetAttributes(entry);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    Directory.Delete(entry);
                }
                else
                {
                    File.Delete(entry);
                }
            }
            else if ((attributes & FileAttributes.Directory) != 0)
            {
                DeleteDirectoryWithoutFollowingLinks(entry);
            }
            else
            {
                File.Delete(entry);
            }
        }
        Directory.Delete(path);
    }

    private static void RejectReparsePoint(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new UnauthorizedAccessException("Setup does not write through a symbolic link or reparse point.");
        }
    }
}
