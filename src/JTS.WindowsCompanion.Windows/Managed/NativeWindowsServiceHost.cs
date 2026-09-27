using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace JTS.WindowsCompanion.Windows.Managed;

public static class NativeWindowsServiceHost
{
    public static int Run(
        string serviceName,
        Func<CancellationToken, Task> worker,
        Action? startupAttestation = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serviceName);
        ArgumentNullException.ThrowIfNull(worker);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows service hosting is available only on Windows.");
        }

        return RunWindows(serviceName, worker, startupAttestation ?? (() => { }));
    }

    [SupportedOSPlatform("windows")]
    private static int RunWindows(
        string serviceName,
        Func<CancellationToken, Task> worker,
        Action startupAttestation)
    {
        var runner = new ServiceRunner(serviceName, worker, startupAttestation);
        return runner.Run();
    }

    [SupportedOSPlatform("windows")]
    private sealed class ServiceRunner
    {
        private readonly string _serviceName;
        private readonly Func<CancellationToken, Task> _worker;
        private readonly Action _startupAttestation;
        private readonly CancellationTokenSource _shutdown = new();
        private readonly ServiceMainFunction _serviceMain;
        private readonly HandlerFunction _handler;
        private IntPtr _statusHandle;
        private uint _checkpoint = 1;

        public ServiceRunner(
            string serviceName,
            Func<CancellationToken, Task> worker,
            Action startupAttestation)
        {
            _serviceName = serviceName;
            _worker = worker;
            _startupAttestation = startupAttestation;
            _serviceMain = ServiceMain;
            _handler = Handler;
        }

        public int Run()
        {
            var table = new[]
            {
                new ServiceTableEntry { ServiceName = _serviceName, ServiceMain = _serviceMain },
                new ServiceTableEntry(),
            };
            if (!StartServiceCtrlDispatcher(table))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return 0;
        }

        private void ServiceMain(uint argumentCount, IntPtr arguments)
        {
            _statusHandle = RegisterServiceCtrlHandlerEx(_serviceName, _handler, IntPtr.Zero);
            if (_statusHandle == IntPtr.Zero)
            {
                return;
            }

            Report(ServiceState.StartPending, acceptedControls: 0, waitHint: 10_000);
            try
            {
                _startupAttestation();
                Report(ServiceState.Running, acceptedControls: 1, waitHint: 0);
                _worker(_shutdown.Token).GetAwaiter().GetResult();
                Report(ServiceState.Stopped, acceptedControls: 0, waitHint: 0);
            }
            catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
            {
                Report(ServiceState.Stopped, acceptedControls: 0, waitHint: 0);
            }
            catch
            {
                Report(ServiceState.Stopped, acceptedControls: 0, waitHint: 0, win32ExitCode: 1066, serviceExitCode: 1);
            }
        }

        private uint Handler(uint control, uint eventType, IntPtr eventData, IntPtr context)
        {
            if (control is 1 or 5)
            {
                Report(ServiceState.StopPending, acceptedControls: 0, waitHint: 10_000);
                _shutdown.Cancel();
            }

            return 0;
        }

        private void Report(
            ServiceState state,
            uint acceptedControls,
            uint waitHint,
            uint win32ExitCode = 0,
            uint serviceExitCode = 0)
        {
            var status = new ServiceStatus
            {
                ServiceType = 0x10,
                CurrentState = state,
                ControlsAccepted = acceptedControls,
                Win32ExitCode = win32ExitCode,
                ServiceSpecificExitCode = serviceExitCode,
                CheckPoint = state is ServiceState.Running or ServiceState.Stopped ? 0 : _checkpoint++,
                WaitHint = waitHint,
            };
            _ = SetServiceStatus(_statusHandle, ref status);
        }
    }

    private enum ServiceState : uint
    {
        Stopped = 1,
        StartPending = 2,
        StopPending = 3,
        Running = 4,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ServiceTableEntry
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? ServiceName;

        public ServiceMainFunction? ServiceMain;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint ServiceType;
        public ServiceState CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void ServiceMainFunction(uint argumentCount, IntPtr arguments);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint HandlerFunction(uint control, uint eventType, IntPtr eventData, IntPtr context);

    [DllImport("advapi32.dll", EntryPoint = "StartServiceCtrlDispatcherW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartServiceCtrlDispatcher([In] ServiceTableEntry[] serviceTable);

    [DllImport("advapi32.dll", EntryPoint = "RegisterServiceCtrlHandlerExW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr RegisterServiceCtrlHandlerEx(
        string serviceName,
        HandlerFunction handler,
        IntPtr context);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetServiceStatus(IntPtr statusHandle, ref ServiceStatus serviceStatus);
}
