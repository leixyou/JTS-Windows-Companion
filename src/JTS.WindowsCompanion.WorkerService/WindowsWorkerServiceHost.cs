using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using JTS.WindowsCompanion.Execution;
using JTS.WindowsCompanion.WorkerIpc;

namespace JTS.WindowsCompanion.WorkerService;

/// <summary>Own-process SCM host, one start/task per process. Does not install or configure a service.</summary>
[SupportedOSPlatform("windows")]
public static class WindowsWorkerServiceHost
{
    public static int Run(Func<WorkerLaunchDescriptor, CancellationToken, Task> worker)
    {
        if (!Environment.Is64BitProcess) throw new PlatformNotSupportedException();
        using var runner = new Host(worker); return runner.Run();
    }
    private sealed class Host(Func<WorkerLaunchDescriptor, CancellationToken, Task> worker) : IDisposable
    {
        private readonly CancellationTokenSource _stop = new();
        private readonly object _gate = new();
        private IntPtr _status;
        private bool _used, _finished, _stopping;
        private uint _checkpoint;
        private int _exit;
        private ServiceMain? _main;
        private Handler? _handler;
        internal int Run()
        {
            _main = Main; _handler = Control;
            var table = new[] { new Table { Name = WorkerLaunchArguments.ServiceName, Main = _main }, new Table() };
            if (!StartServiceCtrlDispatcher(table)) throw new WorkerServiceException("WORKER_SERVICE_DISPATCH_FAILED");
            GC.KeepAlive(_main); GC.KeepAlive(_handler); return _exit;
        }
        private void Main(uint count, IntPtr arguments)
        {
            try
            {
                _status = RegisterServiceCtrlHandlerEx(WorkerLaunchArguments.ServiceName, _handler!, IntPtr.Zero);
                if (_status == IntPtr.Zero) { _exit = 70; return; }
                lock (_gate)
                {
                    if (_used) throw new WorkerServiceException("WORKER_SERVICE_RESTART_REJECTED");
                    _used = true; Report(2);
                }
                if (count != 8) throw new WorkerServiceException("WORKER_SERVICE_ARGUMENTS_INVALID");
                var values = new string[8];
                for (var i = 0; i < 8; i++) values[i] = ReadArgument(Marshal.ReadIntPtr(arguments, i * IntPtr.Size));
                if (values[0] != WorkerLaunchArguments.ServiceName) throw new WorkerServiceException("WORKER_SERVICE_ARGUMENTS_INVALID");
                var descriptor = WorkerLaunchArguments.Decode(values[1..]);
                // Reduce only this SCM service process before Running permits authority attachment or any Worker IPC.
                WindowsStandardAccount.RestrictServiceCurrent(descriptor.WorkerSid);
                lock (_gate)
                {
                    if (_stopping) throw new WorkerServiceException("WORKER_SERVICE_START_CANCELLED");
                    Report(4);
                }
                worker(descriptor, _stop.Token).GetAwaiter().GetResult();
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { _exit = 0; }
            catch { _exit = 70; }
            finally
            {
                lock (_gate)
                {
                    _finished = true;
                    if (_status != IntPtr.Zero)
                        try { Report(1); } catch { _exit = 70; }
                }
            }
        }
        private uint Control(uint control, uint eventType, IntPtr data, IntPtr context)
        {
            try
            {
                lock (_gate)
                {
                    if (_finished) return 0;
                    if (control == 4) return 0;
                    if (control is not (1 or 5)) return 120;
                    if (_stopping) return 0;
                    _stopping = true; Report(3);
                }
                // Never block SCM's global control-dispatch thread on cancellation callbacks.
                ThreadPool.QueueUserWorkItem(_ => { try { _stop.Cancel(); } catch { } });
                _ = Task.Run(async () =>
                {
                    await Task.Delay(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
                    lock (_gate) if (!_finished) Environment.Exit(71); // Actual process exit; never claim a hung Worker stopped.
                });
                return 0;
            }
            catch { return 1064; }
        }
        private void Report(uint state)
        {
            var status = new Status { Type = 0x10, State = state, Accepted = state == 4 ? 5u : 0,
                Checkpoint = state is 2 or 3 ? ++_checkpoint : 0, WaitHint = state is 2 or 3 ? 5000u : 0,
                Win32Exit = state == 1 && _exit != 0 ? 1066u : 0, ServiceExit = state == 1 ? (uint)_exit : 0 };
            if (!SetServiceStatus(_status, ref status)) throw new WorkerServiceException("WORKER_SERVICE_STATUS_FAILED");
        }
        public void Dispose() => _stop.Dispose();
    }
    private static string ReadArgument(IntPtr pointer)
    {
        if (pointer == IntPtr.Zero) throw new WorkerServiceException("WORKER_SERVICE_ARGUMENTS_INVALID");
        var chars = new List<char>();
        for (var i = 0; i <= 1024; i++)
        {
            var c = (char)Marshal.ReadInt16(pointer, i * 2); if (c == 0) return new string(chars.ToArray()); chars.Add(c);
        }
        throw new WorkerServiceException("WORKER_SERVICE_ARGUMENTS_INVALID");
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct Table
    { [MarshalAs(UnmanagedType.LPWStr)] internal string? Name; internal ServiceMain? Main; }
    [StructLayout(LayoutKind.Sequential)] private struct Status
    { internal uint Type, State, Accepted, Win32Exit, ServiceExit, Checkpoint, WaitHint; }
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate void ServiceMain(uint count, IntPtr args);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint Handler(uint control, uint eventType, IntPtr data, IntPtr context);
    [DllImport("advapi32.dll", EntryPoint = "StartServiceCtrlDispatcherW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool StartServiceCtrlDispatcher([In] Table[] table);
    [DllImport("advapi32.dll", EntryPoint = "RegisterServiceCtrlHandlerExW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr RegisterServiceCtrlHandlerEx(string name, Handler handler, IntPtr context);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetServiceStatus(IntPtr handle, ref Status status);
}
