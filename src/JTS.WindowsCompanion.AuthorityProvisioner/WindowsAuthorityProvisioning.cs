using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using JTS.WindowsCompanion.Execution;
using JTS.WindowsCompanion.Pairing;
using JTS.WindowsCompanion.Runtime;
using JTS.WindowsCompanion.WorkerService;

namespace JTS.WindowsCompanion.AuthorityProvisioner;

[SupportedOSPlatform("windows")]
internal static class WindowsAuthorityProvisioning
{
    internal static void Run(Guid enrollment)
    {
        using var current = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        var account = current.User?.Value ?? throw new ProvisioningException("PROVISION_ACCOUNT_REQUIRED");
        WindowsStandardAccount.VerifyCurrent(account);
        using var program = WindowsServiceProgramTrust.Open(Environment.ProcessPath ?? "", CompanionServiceProgram.AuthorityProvisioner);
        var paths = new ProvisioningPaths(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "JTS Terminal", "Companion25"), enrollment);
        paths.RequireStagingOnly();
        // State is authority-private; the intent and its parent remain installer-owned and read-only to that account.
        WindowsProtectedDataPath.Require(paths.FilePath("attempt.json"), account);
        VerifyIntent(paths);
        using var intentLease = new FileStream(paths.Intent, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (intentLease.Length is < 1 or > ProvisioningIntent.MaximumBytes) throw new ProvisioningException("PROVISION_INTENT_INVALID");
        var bytes = new byte[(int)intentLease.Length]; intentLease.ReadExactly(bytes);
        VerifyIntent(paths);
        var intent = ProvisioningIntent.Parse(bytes, enrollment, account, TimeProvider.System);
        byte[]? delegation = null;
        if (intent.DelegationSha256 is not null)
        {
            var requestPath = Path.Combine(paths.Stage, "delegation-request.json");
            VerifyIntent(paths, requestPath);
            using var request = new FileStream(requestPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (request.Length is < 1 or > RelayDelegatedEnrollment.MaximumBytes) throw new ProvisioningException("PROVISION_DELEGATION_INVALID");
            delegation = new byte[(int)request.Length]; request.ReadExactly(delegation);
            if (Convert.ToHexStringLower(SHA256.HashData(delegation)) != intent.DelegationSha256) throw new ProvisioningException("PROVISION_DELEGATION_INVALID");
        }
        var state = new ProvisioningState(new CurrentUserDpapiTaskProtector(), new WindowsIdentityFactory(),
            path => { WindowsProtectedDataPath.Require(path, account); VerifyIntent(paths); }, TimeProvider.System);
        state.Create(paths, intent, delegation);
    }
    private static void VerifyIntent(ProvisioningPaths paths, string? file = null)
    {
        file ??= paths.Intent;
        ProvisioningPaths.RejectLinks(file);
        for (string? path = file; path is not null; path = Path.GetDirectoryName(path))
        {
            var guarded = path == file || path == paths.Stage || path == Path.GetDirectoryName(paths.Stage) || path == paths.Root;
            var sections = AccessControlSections.Owner | AccessControlSections.Access;
            FileSystemSecurity acl = Directory.Exists(path) ? new DirectoryInfo(path).GetAccessControl(sections) : new FileInfo(path).GetAccessControl(sections);
            var descriptor = new RawSecurityDescriptor(acl.GetSecurityDescriptorBinaryForm(), 0);
            if (descriptor.Owner is null || descriptor.DiscretionaryAcl is null) throw new ProvisioningException("PROVISION_INTENT_ACL_REJECTED");
            var entries = new List<ProvisioningAccessEntry>();
            foreach (var item in descriptor.DiscretionaryAcl)
            {
                if (item is not CommonAce ace || ace.IsCallback || ace.AceQualifier is not (AceQualifier.AccessAllowed or AceQualifier.AccessDenied))
                    throw new ProvisioningException("PROVISION_INTENT_ACL_REJECTED");
                entries.Add(new(ace.SecurityIdentifier.Value, ace.AccessMask, ace.AceQualifier == AceQualifier.AccessAllowed,
                    (ace.AceFlags & AceFlags.InheritOnly) != 0));
            }
            ProvisioningIntentAccess.Require(new(descriptor.Owner.Value,
                (descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0, entries.ToArray()), guarded);
        }
    }

    private sealed class WindowsIdentityFactory : IProvisioningIdentityFactory
    {
        public StoredRelayIdentity Create(string path, ProvisioningIntent intent)
            => WindowsRelayIdentityStore.CreateNew(path, intent.EnrollmentId, intent.AuthoritySid);
        public StoredRelayIdentity Open(string path, ProvisioningIntent intent, string deviceId)
            => WindowsRelayIdentityStore.Open(path, intent.EnrollmentId, intent.AuthoritySid, deviceId);
    }
}
