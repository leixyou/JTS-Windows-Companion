namespace JTS.WindowsCompanion.UnattendedInstallation;

// Only an already authenticated schema-2 inventory reaches this role selector.
internal static class InstallationPayloadPlan
{
    internal const string SetupName = "JTS.WindowsCompanion.UnattendedSetup.exe";
    internal static string[] SelectFiles(int schema, IReadOnlyList<string> names)
    {
        var inventory = new HashSet<string>(names, StringComparer.OrdinalIgnoreCase);
        if (schema != 2 || names.Count is < 5 or > 128 || inventory.Count != names.Count
            || InstallationPayload.Names.Any(name => !inventory.Contains(name))
            || !inventory.Contains(SetupName) || !inventory.Contains("e_sqlite3.dll")) Reject();
        foreach (var name in names)
        {
            if (name != Path.GetFileName(name) || name.Contains('\\') || name.Contains(':')) Reject();
            if (!name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                && !InstallationPayload.Names.Contains(name, StringComparer.OrdinalIgnoreCase)
                && !string.Equals(name, SetupName, StringComparison.OrdinalIgnoreCase)) Reject();
        }
        // The native bootstrap owns the UI's lifetime; never install it as a service executable.
        return names.Where(name => !string.Equals(name, SetupName, StringComparison.OrdinalIgnoreCase)).Order(StringComparer.Ordinal).ToArray();
    }
    private static void Reject() => throw new UnattendedInstallationException("INSTALL_PAYLOAD_REJECTED");
}
