using System.Runtime.Versioning;

namespace JTS.WindowsCompanion.UnattendedInstallation;

/// <summary>Explicit installer operations only. A protected coordinator journal supplies SID ownership receipts.</summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsLocalAccountManager
{
    internal LocalAccountIdentity CreateDisabled(string name, string role, Guid enrollment, AccountPassword password)
    {
        if (name != LocalAccountIdentity.AccountName(enrollment, role))
            throw new UnattendedInstallationException("INSTALL_ACCOUNT_IDENTITY_INVALID");
        WindowsAccountInspection.RequireInstaller();
        if (WindowsAccountInspection.Read(name) is not null) throw new UnattendedInstallationException("INSTALL_ACCOUNT_NAME_COLLISION");
        var marker = $"JTS.Companion25/v1/{enrollment:D}/{role}";
        var info = new LocalAccountNative.UserInfo1
        {
            Name = name, Password = password.Pointer, Privilege = 1, Comment = marker,
            Flags = LocalAccountNative.RequiredFlags | LocalAccountNative.Disabled,
        };
        uint status;
        try { status = LocalAccountNative.NetUserAdd(null, 1, ref info, out _); }
        finally { info.Password = IntPtr.Zero; GC.KeepAlive(password); }
        if (status == LocalAccountNative.UserExists) throw new UnattendedInstallationException("INSTALL_ACCOUNT_NAME_COLLISION");
        if (status != 0) throw new UnattendedInstallationException("INSTALL_ACCOUNT_CREATE_FAILED");
        // No automatic cleanup/adoption if this read fails: the coordinator has no durable SID receipt yet.
        var created = WindowsAccountInspection.Read(name) ?? throw new UnattendedInstallationException("INSTALL_ACCOUNT_CREATE_UNCONFIRMED");
        var identity = new LocalAccountIdentity(name, created.Sid, enrollment, role);
        RequireOwned(identity, created);
        RequireFlags(created, disabled: true);
        WindowsAccountInspection.RequireOrdinaryGroups(name);
        return identity;
    }

    internal void VerifyOwned(LocalAccountIdentity identity)
    {
        WindowsAccountInspection.RequireInstaller();
        _ = ReadOwned(identity);
    }

    internal void ConfigureServiceLogon(LocalAccountIdentity identity)
    {
        WindowsAccountInspection.RequireInstaller();
        RequireFlags(ReadOwned(identity), disabled: true);
        WindowsAccountInspection.RequireOrdinaryGroups(identity.Name);
        using var rights = new WindowsAccountRights();
        _ = ReadOwned(identity);
        rights.GrantServiceOnly(identity.Sid);
        RequireFlags(ReadOwned(identity), disabled: true);
    }

    internal void Enable(LocalAccountIdentity identity)
    {
        WindowsAccountInspection.RequireInstaller();
        RequireFlags(ReadOwned(identity), disabled: true);
        WindowsAccountInspection.RequireOrdinaryGroups(identity.Name);
        using var rights = new WindowsAccountRights();
        rights.RequireExpected(identity.Sid, complete: true);
        RequireFlags(ReadOwned(identity), disabled: true);
        var flags = LocalAccountNative.RequiredFlags;
        if (LocalAccountNative.NetUserSetInfo(null, identity.Name, 1008, ref flags, out _) != 0)
            throw new UnattendedInstallationException("INSTALL_ACCOUNT_ENABLE_FAILED");
        RequireFlags(ReadOwned(identity), disabled: false);
        rights.RequireExpected(identity.Sid, complete: true);
    }

    // Only the coordinator may call this after proving no service/job is executing under the account.
    // Disabling an account prevents NEW logons; it does not terminate existing processes or tokens.
    internal void DeleteOwned(LocalAccountIdentity identity)
    {
        WindowsAccountInspection.RequireInstaller();
        var existing = ReadOwned(identity);
        RequireFlags(existing, (existing.Flags & LocalAccountNative.Disabled) != 0);
        using var rights = new WindowsAccountRights();
        rights.RequireExpected(identity.Sid, complete: false);
        _ = ReadOwned(identity);
        var flags = LocalAccountNative.RequiredFlags | LocalAccountNative.Disabled;
        if (LocalAccountNative.NetUserSetInfo(null, identity.Name, 1008, ref flags, out _) != 0)
            throw new UnattendedInstallationException("INSTALL_ACCOUNT_DISABLE_FAILED");
        RequireFlags(ReadOwned(identity), disabled: true);
        rights.RemoveOwned(identity.Sid);
        RequireFlags(ReadOwned(identity), disabled: true);
        if (LocalAccountNative.NetUserDel(null, identity.Name) != 0)
            throw new UnattendedInstallationException("INSTALL_ACCOUNT_DELETE_FAILED");
        if (WindowsAccountInspection.Read(identity.Name) is not null)
            throw new UnattendedInstallationException("INSTALL_ACCOUNT_DELETE_UNCONFIRMED");
    }

    private static LocalAccountSnapshot ReadOwned(LocalAccountIdentity identity)
    {
        identity.Validate();
        var actual = WindowsAccountInspection.Read(identity.Name)
            ?? throw new UnattendedInstallationException("INSTALL_ACCOUNT_OWNERSHIP_UNCONFIRMED");
        RequireOwned(identity, actual); return actual;
    }
    private static void RequireOwned(LocalAccountIdentity identity, LocalAccountSnapshot actual)
    {
        identity.Validate();
        if (actual.Name != identity.Name || actual.Sid != identity.Sid || actual.Marker != identity.Marker)
            throw new UnattendedInstallationException("INSTALL_ACCOUNT_OWNERSHIP_UNCONFIRMED");
    }
    private static void RequireFlags(LocalAccountSnapshot account, bool disabled)
    {
        var required = LocalAccountNative.RequiredFlags | (disabled ? LocalAccountNative.Disabled : 0);
        if (account.Flags != required) throw new UnattendedInstallationException("INSTALL_ACCOUNT_FLAGS_REJECTED");
    }
}
