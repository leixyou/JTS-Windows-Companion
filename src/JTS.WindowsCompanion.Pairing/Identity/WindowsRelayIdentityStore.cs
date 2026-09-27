using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.Pairing;

/// <summary>Explicit identity provisioning/load under the exact Windows authority account. Never installs/enables a route.</summary>
public static class WindowsRelayIdentityStore
{
    public static StoredRelayIdentity CreateNew(string path, Guid enrollmentId, string expectedAccountSid)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows current-user identity protection is required.");
        var full = WindowsIdentityAccess.Require(path, expectedAccountSid);
        return ProtectedRelayIdentityStore.CreateNew(full, enrollmentId, new CurrentUserDpapiTaskProtector(), TimeProvider.System,
            WindowsIdentityAccess.Verifier(full, expectedAccountSid));
    }
    public static StoredRelayIdentity Open(string path, Guid enrollmentId, string expectedAccountSid, string expectedDeviceId)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows current-user identity protection is required.");
        var full = WindowsIdentityAccess.Require(path, expectedAccountSid);
        return ProtectedRelayIdentityStore.Open(full, enrollmentId, expectedDeviceId, new CurrentUserDpapiTaskProtector(), TimeProvider.System,
            WindowsIdentityAccess.Verifier(full, expectedAccountSid));
    }
}

[SupportedOSPlatform("windows")]
internal static class WindowsIdentityAccess
{
    internal static Action Verifier(string path, string account) => () => Require(path, account);
    internal static string Require(string path, string account)
    {
        using var current = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        IdentityAccessPolicy.Account(account, current.User?.Value ?? "");
        // User profile/DPAPI and filesystem ACLs belong to this account, never a supplied password or impersonated caller.
        if (current.ImpersonationLevel != TokenImpersonationLevel.None) throw new RelayIdentityStoreException("IDENTITY_ACCOUNT_REJECTED");
        if (path is not { Length: >= 4 and <= 240 } || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\'
            || path[2..].Contains(':') || path.Contains('/') || path.Split('\\').Any(p => p is "." or ".." || p.EndsWith(' ') || p.EndsWith('.')))
            throw new RelayIdentityStoreException("IDENTITY_PATH_REJECTED");
        var full = PairingStorePath.Validate(path); var parent = Path.GetDirectoryName(full)!;
        string? ancestor = parent;
        while (!string.IsNullOrEmpty(ancestor))
        {
            Verify(new DirectoryInfo(ancestor), account, ancestor == parent, ancestor == parent);
            ancestor = Path.GetDirectoryName(ancestor);
        }
        foreach (var file in new[] { full, full + ".lease" })
            if (File.Exists(file)) Verify(new FileInfo(file), account, true, false);
        return full;
    }
    private static void Verify(FileSystemInfo info, string account, bool privateObject, bool requireProtected)
    {
        var sections = AccessControlSections.Owner | AccessControlSections.Access;
        FileSystemSecurity acl = info is DirectoryInfo dir ? dir.GetAccessControl(sections) : ((FileInfo)info).GetAccessControl(sections);
        var descriptor = new RawSecurityDescriptor(acl.GetSecurityDescriptorBinaryForm(), 0);
        if (descriptor.Owner is null || descriptor.DiscretionaryAcl is null) throw new RelayIdentityStoreException("IDENTITY_ACL_REJECTED");
        var entries = new List<IdentityAccessEntry>();
        foreach (var item in descriptor.DiscretionaryAcl)
        {
            if (item is not CommonAce ace || ace.IsCallback || ace.AceQualifier is not (AceQualifier.AccessAllowed or AceQualifier.AccessDenied))
                throw new RelayIdentityStoreException("IDENTITY_ACL_REJECTED");
            entries.Add(new(ace.SecurityIdentifier.Value, ace.AccessMask, ace.AceQualifier == AceQualifier.AccessAllowed,
                (ace.AceFlags & AceFlags.InheritOnly) != 0));
        }
        IdentityAccessPolicy.Object(new(descriptor.Owner.Value, (descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0, entries.ToArray()),
            account, privateObject, requireProtected);
    }
}
