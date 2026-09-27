using System.Globalization;

namespace JTS.WindowsCompanion.UnattendedInstallation;

internal sealed record LocalAccountIdentity(string Name, string Sid, Guid EnrollmentId, string Role)
{
    internal static string AccountName(Guid enrollmentId, string role)
    {
        if (enrollmentId == Guid.Empty || role is not ("authority" or "worker"))
            throw new UnattendedInstallationException("INSTALL_ACCOUNT_IDENTITY_INVALID");
        return (role == "authority" ? "JTS25A_" : "JTS25W_") + enrollmentId.ToString("N")[..12];
    }

    internal string Marker => $"JTS.Companion25/v1/{EnrollmentId:D}/{Role}";
    internal void Validate()
    {
        if (Name != AccountName(EnrollmentId, Role) || !IsDedicatedSid(Sid))
            throw new UnattendedInstallationException("INSTALL_ACCOUNT_IDENTITY_INVALID");
    }

    private static bool IsDedicatedSid(string sid)
    {
        if (sid is null) return false;
        var parts = sid.Split('-');
        return parts.Length == 8 && sid.StartsWith("S-1-5-21-", StringComparison.Ordinal)
            && parts.Skip(4).All(p => uint.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out var n)
                && n.ToString(CultureInfo.InvariantCulture) == p)
            && uint.Parse(parts[7], CultureInfo.InvariantCulture) >= 1000;
    }
}
