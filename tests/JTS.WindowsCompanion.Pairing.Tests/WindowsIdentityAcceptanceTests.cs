using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using JTS.WindowsCompanion.Relay;
using Xunit;

namespace JTS.WindowsCompanion.Pairing.Tests;

// Explicit opt-in under a pre-provisioned Windows account/directory; never creates accounts or services.
public sealed class WindowsIdentityAcceptanceTests
{
    [WindowsIdentityFact(requireWindows11: true)]
    public Task CurrentUserDpapiAndReopenedUserKeyAuthenticateTls13() => RunNativeTlsAsync(RelayTlsPolicy.Tls13);

    [WindowsIdentityFact]
    public Task CurrentUserDpapiAndReopenedUserKeyAuthenticateExplicitTls12() => RunNativeTlsAsync(RelayTlsPolicy.ExplicitWindows10Tls12);

    private static async Task RunNativeTlsAsync(RelayTlsPolicy policy)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        using var controllerFolder = new NativeIdentityDirectory(); using var companionFolder = new NativeIdentityDirectory();
        string controllerId, companionId;
        using (var identity = WindowsRelayIdentityStore.CreateNew(controllerFolder.Path, controllerFolder.Enrollment, controllerFolder.Account))
            controllerId = identity.Description.DeviceId;
        using (var identity = WindowsRelayIdentityStore.CreateNew(companionFolder.Path, companionFolder.Enrollment, companionFolder.Account))
            companionId = identity.Description.DeviceId;
        using var controller = WindowsRelayIdentityStore.Open(controllerFolder.Path, controllerFolder.Enrollment, controllerFolder.Account, controllerId);
        using var companion = WindowsRelayIdentityStore.Open(companionFolder.Path, companionFolder.Enrollment, companionFolder.Account, companionId);
        await IdentityTransportTests.ExchangeAsync(controller.Identity, companion.Identity, policy);
    }

    [WindowsIdentityFact]
    public void ExpandedFileReadAclIsRejectedBeforeIdentityLoading()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        using var folder = new NativeIdentityDirectory(); string device;
        using (var identity = WindowsRelayIdentityStore.CreateNew(folder.Path, folder.Enrollment, folder.Account)) device = identity.Description.DeviceId;
        var file = new FileInfo(folder.Path); var acl = file.GetAccessControl();
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            FileSystemRights.Read, AccessControlType.Allow));
        file.SetAccessControl(acl);
        var path = folder.Path; var enrollment = folder.Enrollment; var account = folder.Account;
        Assert.Equal("IDENTITY_ACL_REJECTED", Assert.Throws<RelayIdentityStoreException>(() =>
            WindowsRelayIdentityStore.Open(path, enrollment, account, device)).Code);
    }
}

[SupportedOSPlatform("windows")]
internal sealed class NativeIdentityDirectory : IDisposable
{
    private readonly DirectoryInfo _directory;
    internal string Path => System.IO.Path.Combine(_directory.FullName, "identity.sealed");
    internal string Account { get; } = Environment.GetEnvironmentVariable("JTS_IDENTITY_TEST_ACCOUNT_SID")!;
    internal Guid Enrollment { get; } = Guid.NewGuid();
    internal NativeIdentityDirectory()
    {
        // Caller explicitly authorizes a test-only subdirectory inside this existing protected root.
        var root = Environment.GetEnvironmentVariable("JTS_IDENTITY_TEST_DIRECTORY")!;
        if (!System.IO.Path.IsPathFullyQualified(root) || !Directory.Exists(root)) throw new InvalidOperationException("IDENTITY_TEST_ROOT_REQUIRED");
        _directory = Directory.CreateDirectory(System.IO.Path.Combine(root, "jts-identity-acceptance-" + Guid.NewGuid().ToString("N")));
        try
        {
            var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false);
            acl.SetOwner(new SecurityIdentifier(Account));
            foreach (var sid in new[] { Account, IdentityAccessPolicy.SystemSid, IdentityAccessPolicy.AdminSid })
                acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            _directory.SetAccessControl(acl);
        }
        catch { _directory.Delete(); throw; }
    }
    public void Dispose() => _directory.Delete(true);
}

internal sealed class WindowsIdentityFactAttribute : FactAttribute
{
    public WindowsIdentityFactAttribute(bool requireWindows11 = false)
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10) || !Environment.Is64BitProcess)
            Skip = "Requires explicitly provisioned 64-bit Windows; macOS is not native identity/DPAPI/Schannel evidence.";
        else if (requireWindows11 && !OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000))
            Skip = "TLS 1.3 acceptance requires Windows 11; do not downgrade this gate.";
        else if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("JTS_IDENTITY_TEST_ACCOUNT_SID"))
            || string.IsNullOrEmpty(Environment.GetEnvironmentVariable("JTS_IDENTITY_TEST_DIRECTORY")))
            Skip = "Set JTS_IDENTITY_TEST_ACCOUNT_SID and JTS_IDENTITY_TEST_DIRECTORY for the explicitly provisioned account/root.";
    }
}
