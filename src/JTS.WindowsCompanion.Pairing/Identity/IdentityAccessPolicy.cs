using System.Globalization;

namespace JTS.WindowsCompanion.Pairing;

internal sealed record IdentityAccessEntry(string Sid, int Mask, bool Allow, bool InheritOnly);
internal sealed record IdentitySecurityFacts(string Owner, bool Protected, IdentityAccessEntry[] Entries);

internal static class IdentityAccessPolicy
{
    internal const string SystemSid = "S-1-5-18", AdminSid = "S-1-5-32-544";
    internal const string InstallerSid = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    internal static void Account(string expected, string actual)
    {
        var pieces = expected.Split('-');
        if (expected != actual || pieces.Length != 8 || !expected.StartsWith("S-1-5-21-", StringComparison.Ordinal)
            || !pieces.Skip(4).All(p => uint.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out var n)
                && n.ToString(CultureInfo.InvariantCulture) == p) || uint.Parse(pieces[7], CultureInfo.InvariantCulture) < 1000)
            throw new RelayIdentityStoreException("IDENTITY_ACCOUNT_REJECTED");
    }
    internal static void Object(IdentitySecurityFacts facts, string account, bool privateObject, bool requireProtected)
    {
        bool Trusted(string sid) => sid == account || sid is SystemSid or AdminSid or InstallerSid;
        if (!Trusted(facts.Owner) || (requireProtected && !facts.Protected)) throw new RelayIdentityStoreException("IDENTITY_ACL_REJECTED");
        const int replace = 0x10000000 | 0x40000000 | 0x000D0040; // Generic all/write, owner/DACL/delete/delete-child.
        // Private objects have no nontrusted allow ACE at all; ancestors may permit read/traverse/create siblings.
        if (facts.Entries.Any(a => a.Allow && !Trusted(a.Sid) && (privateObject || (!a.InheritOnly && (a.Mask & replace) != 0))))
            throw new RelayIdentityStoreException("IDENTITY_ACL_REJECTED");
    }
}
