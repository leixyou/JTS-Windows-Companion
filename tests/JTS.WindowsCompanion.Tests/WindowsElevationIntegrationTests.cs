using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Principal;
using JTS.WindowsCompanion.Elevation;
using JTS.WindowsCompanion.Windows.Elevation;
using JTS.WindowsCompanion.Windows.Managed;
using JTS.WindowsCompanion.Windows.Security;

namespace JTS.WindowsCompanion.Tests;

public sealed class WindowsElevationIntegrationTests
{
    [WindowsIntegrationFact]
    [SupportedOSPlatform("windows10.0")]
    public void AuthenticodeVerifier_FailsClosedForUnsignedTestAssembly()
    {
        var verifier = new WindowsAuthenticodeTrustVerifier();
        Assert.ThrowsAny<Exception>(() => verifier.CreateSameSignerPolicy(
            typeof(WindowsElevationIntegrationTests).Assembly.Location,
            "target.exe"));
    }

    [WindowsIntegrationFact]
    [SupportedOSPlatform("windows10.0")]
    public async Task ManagedPipe_AcceptsConfiguredCurrentUserClient()
    {
        using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        var sid = identity.User?.Value ?? throw new InvalidOperationException("The test user SID is unavailable.");
        var pipeName = $"JTS.Managed.Test.{Guid.NewGuid():N}";
        await using var server = SecureManagedServicePipe.CreateServer(pipeName, sid);
        await using var client = new NamedPipeClientStream(
            ".",
            pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var accepting = server.WaitForConnectionAsync(timeout.Token);
        await client.ConnectAsync(timeout.Token);
        await accepting;
        Assert.True(SecureManagedServicePipe.IsExpectedClient(server, sid));
    }

    [WindowsInteractiveConsentFact]
    [SupportedOSPlatform("windows10.0")]
    public async Task InteractiveConsent_IsNeverRunUnlessExplicitlyEnabled()
    {
        var directory = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        var action = new ElevatedPowerShellActionDescriptor(
            "interactive-test",
            "Write-Output 'JTS interactive UAC test'",
            directory,
            1_000,
            4_096,
            new Dictionary<string, string>(),
            [new ResolvedElevationDataScope("local-app-data", directory, ElevationScopeAccess.Read)]);
        var approved = await new WindowsElevationConsentPrompt().ConfirmAsync(
            action,
            TimeSpan.FromMinutes(1),
            CancellationToken.None);
        Assert.True(approved, "Approve the explicitly gated full-script consent prompt to complete this test.");
    }

    [WindowsInteractiveConsentFact]
    [SupportedOSPlatform("windows10.0")]
    public async Task InteractiveConsent_CancellationClosesTheDialog()
    {
        var directory = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        var action = new ElevatedPowerShellActionDescriptor(
            "interactive-cancellation-test",
            "Write-Output 'This script must not be approved'",
            directory,
            1_000,
            4_096,
            new Dictionary<string, string>(),
            [new ResolvedElevationDataScope("local-app-data", directory, ElevationScopeAccess.Read)]);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await new WindowsElevationConsentPrompt().ConfirmAsync(
                action,
                TimeSpan.FromMinutes(1),
                cancellation.Token));
    }
}

[AttributeUsage(AttributeTargets.Method)]
public sealed class WindowsInteractiveConsentFactAttribute : FactAttribute
{
    public const string EnvironmentVariable = "JTS_RUN_INTERACTIVE_CONSENT_TESTS";
    public const string LegacyEnvironmentVariable = "JTS_RUN_INTERACTIVE_UAC_TESTS";

    public WindowsInteractiveConsentFactAttribute()
    {
        Skip = GetSkipReason();
    }

    private static string? GetSkipReason()
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10))
        {
            return "Requires Windows 10 or Windows 11.";
        }

        if (!Environment.UserInteractive)
        {
            return "Requires an interactive Windows desktop.";
        }

        using var currentProcess = Process.GetCurrentProcess();
        if (currentProcess.SessionId == 0)
        {
            return "Requires an interactive user session outside Session 0.";
        }

        var explicitlyEnabled = string.Equals(
            Environment.GetEnvironmentVariable(EnvironmentVariable),
            "1",
            StringComparison.Ordinal);
        var legacyEnabled = string.Equals(
            Environment.GetEnvironmentVariable(LegacyEnvironmentVariable),
            "1",
            StringComparison.Ordinal);
        if (!explicitlyEnabled && !legacyEnabled)
        {
            return $"Set {EnvironmentVariable}=1 to run the interactive Companion consent tests.";
        }

        return null;
    }
}
