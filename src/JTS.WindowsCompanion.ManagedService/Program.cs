using System.Text.Json;
using JTS.WindowsCompanion.Managed;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Windows.Managed;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("The JTS managed companion service runs only on Windows 10/11 x64.");
    return 2;
}

ManagedServiceStartupMode startupMode;
try
{
#if JTS_MANAGED_SERVICE_DEBUG_CONSOLE
    startupMode = ManagedServiceStartupArguments.Parse(args, debugConsoleHostEnabled: true);
#else
    startupMode = ManagedServiceStartupArguments.Parse(args, debugConsoleHostEnabled: false);
#endif
}
catch (ArgumentException)
{
    Console.Error.WriteLine("The managed service startup request is invalid.");
    return 2;
}

try
{
    var installRoot = Path.GetFullPath(AppContext.BaseDirectory);
    var configurationPath = Path.Combine(installRoot, "managed-service.json");
    var configurationBytes = File.ReadAllBytes(configurationPath);
    if (configurationBytes.Length is <= 0 or > 64 * 1024
        || (File.GetAttributes(configurationPath) & FileAttributes.ReparsePoint) != 0)
    {
        throw new InvalidDataException("The managed service configuration is invalid.");
    }

    var configuration = JsonSerializer.Deserialize<ManagedServiceConfiguration>(
        configurationBytes,
        ControlMessageSerializer.Options)
        ?? throw new InvalidDataException("The managed service configuration is invalid.");
    configuration.Validate();
    var manifests = ResolveInstallDirectory(installRoot, configuration.ManifestDirectory);
    var handlers = ResolveInstallDirectory(installRoot, configuration.HandlerDirectory);
    var executable = Environment.ProcessPath
        ?? throw new InvalidOperationException("The managed service executable path is unavailable.");
    var processAttestor = ManagedServiceAttestationFactory.CreateForService(executable);
    var verifier = new ReleaseManifestInstalledHandlerVerifier(executable);
    var providers = new InstalledManagedProviderStore(manifests, handlers, verifier);
    var dispatcher = new ManagedServiceDispatcher(
        providers,
        new FixedManagedOperationProcessExecutor(verifier));

    async Task Worker(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            await using var pipe = SecureManagedServicePipe.CreateServer(
                configuration.PipeName,
                configuration.AllowedClientSid);
            await pipe.WaitForConnectionAsync(cancellationToken);
            if (!SecureManagedServicePipe.IsExpectedClient(pipe, configuration.AllowedClientSid))
            {
                continue;
            }

            await dispatcher.HandleOneAsync(pipe, cancellationToken);
        }
    }

    if (startupMode == ManagedServiceStartupMode.DebugConsole)
    {
#if JTS_MANAGED_SERVICE_DEBUG_CONSOLE
        using var shutdown = new CancellationTokenSource();
        Console.CancelKeyPress += (_, eventArguments) =>
        {
            eventArguments.Cancel = true;
            shutdown.Cancel();
        };
        await Worker(shutdown.Token);
        return 0;
#else
        return 2;
#endif
    }

    return NativeWindowsServiceHost.Run(
        ManagedServiceInstallation.ServiceName,
        Worker,
        () => processAttestor.Attest(Environment.ProcessId));
}
catch (OperationCanceledException)
{
    return 0;
}
catch (Exception exception)
{
    // Never emit operation arguments, roots, handler output, credentials, or IPC payloads.
    Console.Error.WriteLine("The managed companion service stopped: {0}", exception.GetType().Name);
    return 1;
}

static string ResolveInstallDirectory(string installRoot, string relativePath)
{
    if (string.IsNullOrWhiteSpace(relativePath)
        || Path.IsPathRooted(relativePath)
        || relativePath.Replace('\\', '/').Split('/').Any(segment => segment is "" or "." or ".."))
    {
        throw new UnauthorizedAccessException("The installed managed service path is invalid.");
    }

    var candidate = Path.GetFullPath(Path.Combine(installRoot, relativePath));
    if (!candidate.StartsWith(installRoot, StringComparison.OrdinalIgnoreCase)
        || !Directory.Exists(candidate)
        || HasReparseSegment(installRoot, candidate))
    {
        throw new UnauthorizedAccessException("The installed managed service directory is unsafe.");
    }

    return candidate;
}

static bool HasReparseSegment(string root, string path)
{
    var current = root;
    foreach (var segment in Path.GetRelativePath(root, path)
                 .Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
    {
        current = Path.Combine(current, segment);
        if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
        {
            return true;
        }
    }

    return false;
}

internal sealed record ManagedServiceConfiguration(
    string PipeName,
    string AllowedClientSid,
    string ManifestDirectory,
    string HandlerDirectory)
{
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(PipeName)
            || PipeName.Length > 128
            || !PipeName.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_')
            || string.IsNullOrWhiteSpace(AllowedClientSid)
            || !AllowedClientSid.StartsWith("S-1-", StringComparison.Ordinal))
        {
            throw new InvalidDataException("The managed service configuration is invalid.");
        }
    }
}
