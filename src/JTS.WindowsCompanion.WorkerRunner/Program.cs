using JTS.WindowsCompanion.Execution;
using JTS.WindowsCompanion.Runtime;
using JTS.WindowsCompanion.WorkerIpc;
using JTS.WindowsCompanion.WorkerService;
using System.Runtime.Versioning;

// Trusted launcher supplies public rendezvous/process metadata only, never a script, key or password in argv.
if (!OperatingSystem.IsWindowsVersionAtLeast(10) || !Environment.Is64BitProcess)
{ Console.Error.WriteLine("WORKER_WINDOWS_REQUIRED"); return 10; }
try
{
    if (args is ["--service"])
        return WindowsWorkerServiceHost.Run(WindowsWorkerApplication.RunWorker);
    var descriptor = WorkerLaunchArguments.Decode(args);
    await WindowsWorkerEndpoint.RunOnceAsync(descriptor, new StandardAccountPowerShellExecutor(descriptor.WorkerSid));
    return 0;
}
catch (ArgumentException) { Console.Error.WriteLine("WORKER_LAUNCH_INVALID"); return 11; }
catch (JobExecutionStateUnknownException) { Console.Error.WriteLine("WORKER_STATE_UNKNOWN"); return 71; }
catch (Exception) { Console.Error.WriteLine("WORKER_SESSION_FAILED"); return 70; }

[SupportedOSPlatform("windows")]
internal static class WindowsWorkerApplication
{
    internal static Task RunWorker(WorkerLaunchDescriptor launch, CancellationToken token)
        => WindowsWorkerEndpoint.RunOnceAsync(launch, new StandardAccountPowerShellExecutor(launch.WorkerSid), token);
}
