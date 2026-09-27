using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Security.Cryptography;

namespace JTS.WindowsCompanion.UnattendedInstallation;

[SupportedOSPlatform("windows")]
internal sealed class WindowsInstallationStorage : IDisposable
{
    private const string AdminAcl = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
    private const string ReadAcl = AdminAcl + "(A;OICI;0x1200a9;;;AU)";
    internal string Root { get; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "JTS Terminal", "Companion25");
    internal string ProgramDirectory { get; }
    internal string Stage { get; }
    internal string State => Path.Combine(Stage, "state");
    internal string Live => Path.Combine(Root, "authority");
    internal string JournalPath => Path.Combine(Root, ".install", "transaction.json");
    private readonly FileStream _lease;
    private bool _programOwned, _stageOwned, _published;
    internal WindowsInstallationStorage(Guid enrollment)
    {
        ProgramDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "JTS Terminal", "Companion25", enrollment.ToString("D"));
        Stage = Path.Combine(Root, ".provision", enrollment.ToString("D"));
        EnsureParent(Path.GetDirectoryName(Root)!); EnsureParent(Root);
        EnsurePrivate(Path.Combine(Root, ".install"), AdminAcl);
        var leasePath = Path.Combine(Root, ".install", "setup.lock"); InstallJournal.RejectLinks(leasePath);
        _lease = new FileStream(leasePath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        try
        {
            RequireAbsent(Live); RequireAbsent(JournalPath); RequireAbsent(JournalPath + ".pending"); RequireAbsent(ProgramDirectory); RequireAbsent(Stage);
        }
        catch { _lease.Dispose(); throw; }
    }
    internal void PrepareStage(InstallSnapshot snapshot, InstallationPayload payload, DateTimeOffset now, byte[]? delegation = null)
    {
        var sid = snapshot.Authority!.Sid;
        EnsureParent(Path.GetDirectoryName(Path.GetDirectoryName(ProgramDirectory)!)!);
        EnsureParent(Path.GetDirectoryName(ProgramDirectory)!);
        CreateNew(ProgramDirectory, ReadAcl); _programOwned = true; payload.CopyNew(ProgramDirectory);
        EnsureParent(Path.GetDirectoryName(Stage)!);
        CreateNew(Stage, AdminAcl + $"(A;OICI;0x1200a9;;;{sid})"); _stageOwned = true;
        CreateNew(State, AdminAcl + $"(A;OICI;FA;;;{sid})");
        var intent = new Dictionary<string, object> { ["schemaVersion"] = 1, ["operation"] = "initialize-new-authority", ["enrollmentId"] = snapshot.EnrollmentId,
            ["authoritySid"] = sid, ["workerSid"] = snapshot.Worker!.Sid, ["createdAt"] = now.ToString("O"), ["expiresAt"] = now.AddMinutes(20).ToString("O") };
        if (delegation is not null)
        {
            intent["delegationSha256"] = Convert.ToHexStringLower(SHA256.HashData(delegation));
            var requestPath = Path.Combine(Stage, "delegation-request.json"); WriteNew(requestPath, delegation);
            var requestAcl = new FileSecurity(); requestAcl.SetSecurityDescriptorSddlForm($"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;{sid})");
            new FileInfo(requestPath).SetAccessControl(requestAcl);
        }
        WriteNew(Path.Combine(Stage, "intent.json"), JsonSerializer.SerializeToUtf8Bytes(intent));
        var acl = new FileSecurity(); acl.SetSecurityDescriptorSddlForm($"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;{sid})");
        new FileInfo(Path.Combine(Stage, "intent.json")).SetAccessControl(acl);
    }
    internal void Publish(InstallSnapshot snapshot)
    {
        RequireAbsent(Live); InstallJournal.RejectLinks(State);
        var config = new { schemaVersion = 1, enabled = true, enrollmentId = snapshot.EnrollmentId, deviceId = snapshot.DeviceId,
            authoritySid = snapshot.Authority!.Sid, relayOrigin = snapshot.RelayOrigin,
            worker = new { accountName = @".\" + snapshot.Worker!.Name, accountSid = snapshot.Worker.Sid,
                executablePath = Path.Combine(ProgramDirectory, "JTS.WindowsCompanion.WorkerRunner.exe") } };
        WriteNew(Path.Combine(State, "authority.json"), JsonSerializer.SerializeToUtf8Bytes(config));
        CreateNew(Path.Combine(Root, "shared"), AdminAcl + $"(A;OICI;FA;;;{snapshot.Authority.Sid})(A;OICI;FA;;;{snapshot.Worker.Sid})");
        Directory.Move(State, Live); _published = true;
    }
    internal void RetainFailedFiles()
    {
        // Recoverable quarantine, not recursive deletion; only paths this in-process transaction created.
        if (_published) { RequireAbsent(Stage + ".failed-live"); Directory.Move(Live, Stage + ".failed-live"); _published = false; }
        if (_stageOwned) { RequireAbsent(Stage + ".failed"); Directory.Move(Stage, Stage + ".failed"); _stageOwned = false; }
        if (_programOwned) { RequireAbsent(ProgramDirectory + ".failed"); Directory.Move(ProgramDirectory, ProgramDirectory + ".failed"); _programOwned = false; }
    }
    private static void EnsureParent(string path) => EnsurePrivate(path, ReadAcl);
    private static void EnsurePrivate(string path, string sddl)
    {
        InstallJournal.RejectLinks(path); RequireSafeAncestors(Path.GetDirectoryName(path)!);
        if (!Directory.Exists(path)) { CreateNew(path, sddl); return; }
        var security = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        var descriptor = new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0);
        if (descriptor.Owner?.Value is not ("S-1-5-32-544" or "S-1-5-18") || descriptor.DiscretionaryAcl is null
            || (descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0) throw new UnattendedInstallationException("INSTALL_EXISTING_DIRECTORY_UNTRUSTED");
        foreach (var item in descriptor.DiscretionaryAcl)
        {
            if (item is not CommonAce ace || ace.IsCallback || ace.AceQualifier is not (AceQualifier.AccessAllowed or AceQualifier.AccessDenied))
                throw new UnattendedInstallationException("INSTALL_EXISTING_DIRECTORY_UNTRUSTED");
            if (ace.AceQualifier == AceQualifier.AccessAllowed && ace.SecurityIdentifier.Value is not ("S-1-5-32-544" or "S-1-5-18")
                && ((ace.AccessMask & (0x500D0156)) != 0 || sddl == AdminAcl)) throw new UnattendedInstallationException("INSTALL_EXISTING_DIRECTORY_UNTRUSTED");
        }
    }
    private static void CreateNew(string path, string sddl)
    {
        RequireAbsent(path); InstallJournal.RejectLinks(path); RequireSafeAncestors(Path.GetDirectoryName(path)!);
        WindowsExclusiveDirectory.Create(path, sddl);
    }
    private static void WriteNew(string path, byte[] bytes)
    {
        InstallJournal.RejectLinks(path);
        using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
        output.Write(bytes); output.Flush(flushToDisk: true);
    }
    private static void RequireAbsent(string path)
    {
        try { _ = File.GetAttributes(path); }
        catch (FileNotFoundException) { return; }
        catch (DirectoryNotFoundException) { return; }
        throw new UnattendedInstallationException("INSTALL_EXISTING_STATE_REQUIRES_LOCAL_REVIEW");
    }
    private static void RequireSafeAncestors(string path)
    {
        for (string? current = path; current is not null; current = Path.GetDirectoryName(current))
        {
            var acl = new DirectoryInfo(current).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
            var descriptor = new RawSecurityDescriptor(acl.GetSecurityDescriptorBinaryForm(), 0);
            static bool Trusted(string? sid) => sid is "S-1-5-32-544" or "S-1-5-18" or "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
            if (!Trusted(descriptor.Owner?.Value) || descriptor.DiscretionaryAcl is null) throw new UnattendedInstallationException("INSTALL_ANCESTOR_UNTRUSTED");
            foreach (var entry in descriptor.DiscretionaryAcl)
            {
                if (entry is not CommonAce ace || ace.IsCallback || ace.AceQualifier is not (AceQualifier.AccessAllowed or AceQualifier.AccessDenied))
                    throw new UnattendedInstallationException("INSTALL_ANCESTOR_UNTRUSTED");
                if (ace.AceQualifier == AceQualifier.AccessAllowed && (ace.AceFlags & AceFlags.InheritOnly) == 0
                    && !Trusted(ace.SecurityIdentifier.Value) && (ace.AccessMask & 0x500D0040) != 0)
                    throw new UnattendedInstallationException("INSTALL_ANCESTOR_UNTRUSTED");
            }
        }
    }
    public void Dispose() => _lease.Dispose();
}
