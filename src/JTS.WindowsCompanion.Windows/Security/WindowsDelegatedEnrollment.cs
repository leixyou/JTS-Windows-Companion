using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;
using System.Security.Principal;
using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.Windows.Security;

public static class WindowsDelegatedEnrollment
{
    public static CompanionDelegatedEnrollmentRequest ReadRequest(string path, string sha256, DateTimeOffset now)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("An enrollment request cannot be a reparse point.");
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length is <= 0 or > CompanionDelegatedEnrollmentValidation.MaximumRequestBytes)
            throw new InvalidDataException("The enrollment request size is invalid.");
        var bytes = new byte[(int)input.Length];
        input.ReadExactly(bytes);
        return CompanionDelegatedEnrollmentValidation.Parse(bytes, sha256, now);
    }

    [SupportedOSPlatform("windows")]
    public static async ValueTask<CompanionPeerGrant> PrepareAsync(
        string stateRoot, CompanionDelegatedEnrollmentRequest request, string sha256, CancellationToken cancellationToken)
    {
        using var identity = new DpapiCompanionIdentity(Path.Combine(stateRoot, "identity.v1.json"));
        var metadata = await identity.GetExistingMetadataAsync(cancellationToken).ConfigureAwait(false);
        using var user = WindowsIdentity.GetCurrent();
        return CreateGrant(request, sha256, metadata,
            user.User?.Value ?? throw new UnauthorizedAccessException("The current Windows user SID is unavailable."),
            Process.GetCurrentProcess().SessionId, DateTimeOffset.UtcNow);
    }

    public static CompanionPeerGrant CreateGrant(
        CompanionDelegatedEnrollmentRequest request, string sha256, CompanionIdentityMetadata windowsIdentity,
        string windowsUserSid, int windowsSessionId, DateTimeOffset now)
    {
        request = CompanionDelegatedEnrollmentValidation.ValidateRequest(request, now);
        CompanionDelegatedEnrollmentValidation.ValidateWindowsBinding(request, windowsIdentity);
        var receipt = new CompanionDelegatedConsentReceipt(
            request.SchemaVersion, request.GrantId, request.AuthorizationSource, request.TargetId, request.TargetBinding,
            request.MacIdentity, request.ExpectedWindows, request.IssuedAtUtc, request.ExpiresAtUtc,
            request.AuthorizationReference, sha256, windowsUserSid, windowsSessionId, now);
        receipt = CompanionDelegatedEnrollmentValidation.NormalizeReceipt(receipt, request.MacIdentity);
        return new CompanionPeerGrant(request.MacIdentity, now, receipt);
    }
}
