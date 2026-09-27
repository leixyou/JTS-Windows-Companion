using JTS.WindowsCompanion.Agent;
using JTS.WindowsCompanion.Automation;
using JTS.WindowsCompanion.Elevation;
using JTS.WindowsCompanion.Files;
using JTS.WindowsCompanion.Lifecycle;
using JTS.WindowsCompanion.Managed;
using JTS.WindowsCompanion.Security;
using JTS.WindowsCompanion.Shell;
using JTS.WindowsCompanion.Transfers;
using JTS.WindowsCompanion.Windows.Automation;
using JTS.WindowsCompanion.Windows.Diagnostics;
using JTS.WindowsCompanion.Windows.Elevation;
using JTS.WindowsCompanion.Windows.Managed;
using JTS.WindowsCompanion.Windows.Security;
using JTS.WindowsCompanion.Windows.Transport;
using JTS.WindowsCompanion.Worker;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("JTS Windows Companion runs only on Windows 10/11 x64.");
    return 2;
}

var currentExecutable = Environment.ProcessPath;
var localApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
if (string.IsNullOrWhiteSpace(currentExecutable) || string.IsNullOrWhiteSpace(localApplicationData))
{
    Console.Error.WriteLine("The Windows Companion installation path is unavailable.");
    return 3;
}
var expectedInstallRoot = CompanionInstallationContract.InstallRoot(localApplicationData);
CompanionAgentStartupGateResult startupGateResult;
try
{
    startupGateResult = CompanionAgentStartupGate.WaitForStableInstalledImage(
        currentExecutable,
        Path.Combine(expectedInstallRoot, CompanionInstallationContract.AgentFileName),
        Path.Combine(
            Directory.GetParent(expectedInstallRoot)?.FullName
                ?? throw new InvalidOperationException("The Windows Companion installation parent is unavailable."),
            CompanionInstallationContract.OperationLockFileName),
        Timeout.InfiniteTimeSpan);
}
catch (Exception exception) when (
    exception is IOException or
    UnauthorizedAccessException or
    InvalidDataException or
    ArgumentException)
{
    Console.Error.WriteLine("The Windows Companion setup coordination state is invalid.");
    return 3;
}
if (startupGateResult == CompanionAgentStartupGateResult.Superseded)
{
    return 0;
}
if (startupGateResult == CompanionAgentStartupGateResult.TimedOut)
{
    Console.Error.WriteLine("Another Windows Companion setup operation did not finish in time.");
    return 3;
}

AgentOptions options;
try
{
    options = AgentOptions.Parse(args);
}
catch (ArgumentException)
{
    Console.Error.WriteLine("Invalid Windows Companion arguments.");
    Console.Error.WriteLine("Usage: JTS.WindowsCompanion.Agent [--root id=path] [--read-only-root id=path] [--vrc-worker path.exe --vrc-worker-sha256 digest] [--uac-broker path.exe] [--managed-service-pipe name]");
    return 2;
}

var identityPath = Path.Combine(localApplicationData, "JTSTerminal", "WindowsCompanion", "identity.v1.json");
var pairedPeerPath = Path.Combine(localApplicationData, "JTSTerminal", "WindowsCompanion", "paired-peer.v1.json");
var transferRoot = Path.Combine(localApplicationData, "JTSTerminal", "WindowsCompanion", "Transfers");
using var identity = new DpapiCompanionIdentity(identityPath);
using var pairedPeers = new DpapiCompanionPeerStore(pairedPeerPath);
using var shutdown = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArguments) =>
{
    eventArguments.Cancel = true;
    shutdown.Cancel();
};

try
{
    var readinessAttempted = false;
    async ValueTask NotifyReadyOnce(CancellationToken cancellationToken)
    {
        if (readinessAttempted || options.StartupReadyPipeName is not { } name) return;
        readinessAttempted = true;
        await CompanionAgentReadinessNotifier.TryNotifyAsync(name, cancellationToken);
    }
    await CompanionReconnectLoop.RunAsync(RunSessionAsync, shutdown.Token,
        (failure, interval) => Console.Error.WriteLine(
            "Windows Companion channel retry: operation={0} nativeErrorCode={1} delaySeconds={2}",
            failure?.Operation ?? "closed", failure?.NativeErrorCode ?? 0, (int)interval.TotalSeconds));

    async Task RunSessionAsync(CancellationToken sessionToken)
    {
        var events = new ConsoleSecurityEventSink();
        var sensitiveInteractions = new CompanionSensitiveInteractionCoordinator();
        var authorization = new CompanionAuthorizationSession(
            identity,
            pairedPeers,
            new WindowsCompanionPairingConsentPrompt(),
            sensitiveInteractions: sensitiveInteractions);
        await using var channel = new WtsDynamicVirtualChannel(events: events);
        await using var transfers = new BinaryTransferCoordinator(transferRoot);
        var sandbox = options.FileRoots.Count > 0
            ? new FileSandbox(options.FileRoots)
            : null;
        using var files = sandbox is not null
            ? new SandboxedFileService(sandbox)
            : null;
        var shell = sandbox is not null
            ? new CurrentUserPowerShellExecutor(new CurrentUserShellPolicy(sandbox))
            : null;
        IUiAutomationService automation = new WindowsUiAutomationService();
        VrcFactoryWorkerBridge? vrcWorker;
        try
        {
            vrcWorker = options.VrcWorker is { } workerInstallation
                ? new VrcFactoryWorkerBridge(
                    workerInstallation.ExecutablePath,
                    workerInstallation.ExecutableSha256,
                    transfers,
                    new VrcEnvelopeSecurity(identity, authorization))
                : null;
        }
        catch (ArgumentException)
        {
            Console.Error.WriteLine("The installed VRC worker configuration is invalid.");
            throw;
        }
        IElevationBrokerClient elevationBroker;
        try
        {
            elevationBroker = options.UacBrokerExecutablePath is { } brokerPath && sandbox is not null
                ? new UacElevationBrokerClient(brokerPath, sandbox)
                : UnavailableElevationBrokerClient.Instance;
        }
        catch (Exception exception) when (exception is ArgumentException
            or UnauthorizedAccessException
            or InvalidOperationException
            or System.Security.Cryptography.CryptographicException)
        {
            Console.Error.WriteLine("The configured UAC broker failed its authenticated release-manifest policy.");
            throw;
        }

        await using var elevationBrokerLifetime = elevationBroker;
        IManagedServiceClient managedService;
        try
        {
            managedService = options.ManagedServicePipeName is { } managedPipeName
                ? new NamedPipeManagedServiceClient(managedPipeName)
                : UnavailableManagedServiceClient.Instance;
        }
        catch (Exception exception) when (exception is ArgumentException
            or UnauthorizedAccessException
            or InvalidOperationException
            or System.Security.Cryptography.CryptographicException)
        {
            Console.Error.WriteLine("The configured managed service failed its authenticated release-manifest policy.");
            throw;
        }

        var router = new CompanionRequestRouter(authorization);
        BuiltInMethodRegistrar.Register(
            router,
            identity,
            authorization,
            automation,
            files,
            shell,
            vrcWorker,
            transfers,
            elevationBroker,
            managedService,
            sensitiveInteractions);
        var agent = new CompanionAgent(
            channel, router, transfers: transfers, events: events,
            frameAuthenticator: new CompanionFrameAuthenticator(identity, authorization));
        await agent.RunAsync(NotifyReadyOnce, sessionToken);
    }
    return 0;
}
catch (OperationCanceledException) when (shutdown.IsCancellationRequested)
{
    return 0;
}
catch (Exception exception)
{
    // Do not include protocol payloads, command text, credentials, or process output.
    Console.Error.WriteLine("Windows Companion stopped: {0}", CompanionTerminalFailureDiagnostic.Describe(exception));
    return 1;
}
