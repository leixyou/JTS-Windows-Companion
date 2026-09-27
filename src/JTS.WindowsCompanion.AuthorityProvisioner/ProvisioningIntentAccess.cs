namespace JTS.WindowsCompanion.AuthorityProvisioner;

internal sealed record ProvisioningAccessEntry(string Sid, int Mask, bool Allow, bool InheritOnly = false);
internal sealed record ProvisioningSecurity(string Owner, bool Protected, ProvisioningAccessEntry[] Entries);

internal static class ProvisioningIntentAccess
{
    internal const string SystemSid = "S-1-5-18", AdminSid = "S-1-5-32-544";
    internal const string InstallerSid = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    internal static void Require(ProvisioningSecurity facts, bool protectedObject)
    {
        static bool Installer(string sid) => sid is SystemSid or AdminSid or InstallerSid;
        if (!Installer(facts.Owner) || (protectedObject && !facts.Protected)) throw Rejected();
        const int replace = 0x10000000 | 0x40000000 | 0x000D0040;
        var mutation = replace | (protectedObject ? 0x116 : 0); // Also reject new/changed content at the installer-owned boundaries.
        if (facts.Entries.Any(a => a.Allow && !Installer(a.Sid) && (protectedObject || !a.InheritOnly) && (a.Mask & mutation) != 0))
            throw Rejected();
    }
    private static ProvisioningException Rejected() => new("PROVISION_INTENT_ACL_REJECTED");
}
