using System.Diagnostics;
using System.IO.Pipes;
using JTS.WindowsCompanion.Elevation;
using JTS.WindowsCompanion.Windows.Elevation;
using JTS.WindowsCompanion.Windows.Security;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("The JTS UAC broker runs only on Windows 10/11 x64.");
    return 2;
}

if (!TryParseArguments(args, out var pipeName, out var nonce, out var cancellationEventName))
{
    Console.Error.WriteLine("The UAC broker startup request is invalid.");
    return 2;
}

var elevation = new WindowsProcessElevationVerifier();
if (!elevation.IsElevated)
{
    Console.Error.WriteLine("The UAC broker was not elevated by Windows.");
    return 3;
}

try
{
    using var shutdown = new CancellationTokenSource(ElevationLeaseManager.MaximumDuration + TimeSpan.FromSeconds(30));
    using var cancellationEvent = EventWaitHandle.OpenExisting(cancellationEventName);
    using var releaseCancellation = new CancellationTokenSource();
    using var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(
        shutdown.Token,
        releaseCancellation.Token);
    using var cancellationRegistration = new RegisteredWaitHandleScope(
        ThreadPool.RegisterWaitForSingleObject(
            cancellationEvent,
            (_, _) => releaseCancellation.Cancel(),
            null,
            Timeout.Infinite,
            executeOnlyOnce: true));
    await using var pipe = new NamedPipeClientStream(
        ".",
        pipeName,
        PipeDirection.InOut,
        PipeOptions.Asynchronous);
    await pipe.ConnectAsync(30_000, linkedCancellation.Token);

    var serverProcessId = NamedPipePeerProcess.GetServerProcessId(pipe);
    using var serverProcess = Process.GetProcessById(serverProcessId);
    var serverExecutable = serverProcess.MainModule?.FileName
        ?? throw new UnauthorizedAccessException("The pipe server executable could not be identified.");
    var brokerExecutable = Environment.ProcessPath
        ?? throw new UnauthorizedAccessException("The broker executable path could not be identified.");
    var verifier = ReleaseManifestExecutableTrustVerifier.ForExecutable(brokerExecutable);
    // Authenticate the actual pipe peer against this broker's release, not a peer-selected manifest.
    using var serverFileLock = verifier.OpenVerifiedFile(serverExecutable, "JTS.WindowsCompanion.Agent.exe");

    using var leases = new ElevationLeaseManager();
    var session = new ElevationBrokerSession(
        leases,
        new ElevatedPowerShellExecutor(elevation));
    await session.RunAsync(pipe, nonce, Environment.ProcessId, linkedCancellation.Token);
    return 0;
}
catch (OperationCanceledException)
{
    return 0;
}
catch (Exception exception)
{
    // Never emit the script, paths, credentials, environment, or broker payload.
    Console.Error.WriteLine("The UAC broker stopped: {0}", exception.GetType().Name);
    return 1;
}

static bool TryParseArguments(
    string[] arguments,
    out string pipeName,
    out string nonce,
    out string cancellationEventName)
{
    pipeName = string.Empty;
    nonce = string.Empty;
    cancellationEventName = string.Empty;
    if (arguments.Length != 6)
    {
        return false;
    }

    for (var index = 0; index < arguments.Length; index += 2)
    {
        switch (arguments[index])
        {
            case "--pipe":
                pipeName = arguments[index + 1];
                break;
            case "--nonce":
                nonce = arguments[index + 1];
                break;
            case "--cancel-event":
                cancellationEventName = arguments[index + 1];
                break;
            default:
                return false;
        }
    }

    return pipeName.Length is > 0 and <= 128
        && pipeName.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-')
        && nonce.Length == 64
        && nonce.All(char.IsAsciiHexDigit)
        && cancellationEventName.StartsWith("Local\\JTS.Terminal.Elevation.Cancel.", StringComparison.Ordinal)
        && cancellationEventName.Length <= 128
        && cancellationEventName["Local\\".Length..]
            .All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-');
}

sealed class RegisteredWaitHandleScope : IDisposable
{
    private RegisteredWaitHandle? _registration;

    public RegisteredWaitHandleScope(RegisteredWaitHandle registration)
    {
        _registration = registration;
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _registration, null)?.Unregister(null);
    }
}
