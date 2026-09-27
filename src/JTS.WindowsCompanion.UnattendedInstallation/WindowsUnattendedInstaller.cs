using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Pairing;

namespace JTS.WindowsCompanion.UnattendedInstallation;

public sealed record InstalledUnattendedSupport(Guid EnrollmentId, string DeviceId, string RelayOrigin, string? PublicEnrollmentJson = null);

/// <summary>First install only, through a visible elevated Windows setup host. Never called by a relay/MCP request.</summary>
public static class WindowsUnattendedInstaller
{
    public static Task<InstalledUnattendedSupport> InstallWithConsentAsync(string bundleDirectory, string relayOrigin, CancellationToken stop = default)
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10) || RuntimeInformation.ProcessArchitecture != Architecture.X64)
            throw new PlatformNotSupportedException("UNATTENDED_INSTALL_WINDOWS_REQUIRED");
        return InstallWindowsAsync(bundleDirectory, InstallSnapshot.Origin(relayOrigin), null, stop);
    }
    public static Task<InstalledUnattendedSupport> InstallDelegatedAsync(string bundleDirectory, string relayOrigin,
        byte[] enrollmentRequest, string expectedSha256, CancellationToken stop = default)
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10) || RuntimeInformation.ProcessArchitecture != Architecture.X64)
            throw new PlatformNotSupportedException("UNATTENDED_INSTALL_WINDOWS_REQUIRED");
        if (!InstallSnapshot.Hash(expectedSha256) || Convert.ToHexStringLower(SHA256.HashData(enrollmentRequest)) != expectedSha256)
            throw new UnattendedInstallationException("INSTALL_DELEGATION_HASH_MISMATCH");
        _ = RelayDelegatedEnrollment.Parse(enrollmentRequest);
        return InstallWindowsAsync(bundleDirectory, InstallSnapshot.Origin(relayOrigin), enrollmentRequest.ToArray(), stop);
    }
    [SupportedOSPlatform("windows")]
    private static async Task<InstalledUnattendedSupport> InstallWindowsAsync(string bundleDirectory, Uri relayOrigin, byte[]? delegationBytes, CancellationToken stop)
    {
        stop.ThrowIfCancellationRequested();
        using var token = OpenIdentityForMembershipChecks();
        using var process = Process.GetCurrentProcess();
        if (!Environment.UserInteractive || process.SessionId == 0 || token.IsSystem || token.ImpersonationLevel != TokenImpersonationLevel.None
            || !new WindowsPrincipal(token).IsInRole(WindowsBuiltInRole.Administrator))
            throw new UnattendedInstallationException("INSTALL_INTERACTIVE_ELEVATED_ADMIN_REQUIRED");
        using var payload = new InstallationPayload(bundleDirectory);
        // The local setup action (or its explicit CLI) authorizes installation. Windows elevation is still required.
        // Pairing is delegated by the owner's existing AI-control setting, not another confirmation dialog.
        stop.ThrowIfCancellationRequested();
        var enrollment = Guid.NewGuid();
        using var storage = new WindowsInstallationStorage(enrollment);
        var snapshot = new InstallSnapshot(1, enrollment, relayOrigin.AbsoluteUri, payload.Manifest.ReleaseId,
            payload.Manifest.PayloadSha256.ToLowerInvariant(), InstallPhase.Prepared);
        var journal = new InstallJournal(storage.JournalPath, snapshot);
        var delegation = delegationBytes is null ? null : RelayDelegatedEnrollment.Parse(delegationBytes);
        using var actions = new WindowsInstallationActions(enrollment, storage, payload, delegationBytes);
        var installed = await new FirstInstallation(journal, actions).RunAsync(stop).ConfigureAwait(false);
        // SCM Running is local startup only; no peer is paired and no public/Windows acceptance is claimed here.
        var exported = delegation is null ? null : RelayEnrollmentExport.Create(Environment.MachineName,
            installed.RelayOrigin, actions.PublicKeySpkiBase64, installed.DeviceId, delegation);
        return new(installed.EnrollmentId, installed.DeviceId!, installed.RelayOrigin, exported);
    }
    [SupportedOSPlatform("windows")]
    internal static WindowsIdentity OpenIdentityForMembershipChecks()
        // IsInRole duplicates the current token to query effective membership; Query-only handles fail on Windows.
        => WindowsIdentity.GetCurrent(TokenAccessLevels.Query | TokenAccessLevels.Duplicate);

}
