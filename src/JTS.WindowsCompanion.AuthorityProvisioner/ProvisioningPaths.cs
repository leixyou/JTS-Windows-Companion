namespace JTS.WindowsCompanion.AuthorityProvisioner;

internal sealed class ProvisioningPaths
{
    internal string Root { get; }
    internal Guid EnrollmentId { get; }
    internal string Stage { get; }
    internal string State { get; }
    internal string Intent => Path.Combine(Stage, "intent.json");
    internal string Live => Path.Combine(Root, "authority");
    internal ProvisioningPaths(string root, Guid enrollment)
    {
        if (!Path.IsPathFullyQualified(root) || enrollment == Guid.Empty) throw new ProvisioningException("PROVISION_PATH_REJECTED");
        EnrollmentId = enrollment; Root = Path.GetFullPath(root); Stage = Path.Combine(Root, ".provision", enrollment.ToString("D"));
        State = Path.Combine(Stage, "state");
    }
    internal void RequireStagingOnly()
    {
        RejectLinks(State);
        if (!Directory.Exists(State)) throw new ProvisioningException("PROVISION_STAGE_NOT_PREPARED");
        if (Exists(Live)) throw new ProvisioningException("PROVISION_EXISTING_INSTALLATION");
    }
    internal string FilePath(string name) => Path.Combine(State, name);
    internal static void RejectLinks(string path)
    {
        for (string? current = path; current is not null; current = Path.GetDirectoryName(current))
            if (Exists(current) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new ProvisioningException("PROVISION_LINK_REJECTED");
    }
    private static bool Exists(string path)
    {
        try { _ = File.GetAttributes(path); return true; }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
    }
}
