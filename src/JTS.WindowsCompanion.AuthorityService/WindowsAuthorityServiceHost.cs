using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace JTS.WindowsCompanion.AuthorityService;

[SupportedOSPlatform("windows")]
internal sealed class WindowsAuthorityServiceHost : IDisposable
{
    private readonly object _gate = new();
    private readonly CancellationTokenSource _stop = new();
    private readonly ServiceMain _main;
    private readonly Handler _handler;
    private IntPtr _status;
    private bool _used, _running, _stopping, _finished;
    private uint _checkpoint;
    private int _exit;
    private WindowsAuthorityServiceHost() { _main = Main; _handler = Control; }
    internal static int Run()
    {
        using var host = new WindowsAuthorityServiceHost();
        var table = new[] { new Table { Name = AuthorityConfiguration.ServiceName, Main = host._main }, new Table() };
        if (!StartServiceCtrlDispatcher(table)) throw new AuthorityException("AUTHORITY_SCM_DISPATCH_FAILED");
        GC.KeepAlive(host._main); GC.KeepAlive(host._handler); return host._exit;
    }
    private void Main(uint count, IntPtr arguments)
    {
        try
        {
            _status = RegisterServiceCtrlHandlerEx(AuthorityConfiguration.ServiceName, _handler, IntPtr.Zero);
            if (_status == IntPtr.Zero) throw new AuthorityException("AUTHORITY_SCM_HANDLER_FAILED");
            lock (_gate)
            {
                if (_used) throw new AuthorityException("AUTHORITY_SCM_RESTART_REJECTED");
                _used = true;
            }
            if (count != 1 || arguments == IntPtr.Zero || ReadName(Marshal.ReadIntPtr(arguments)) != AuthorityConfiguration.ServiceName)
                throw new AuthorityException("AUTHORITY_SCM_ARGUMENTS_REJECTED");
            Watchdog(TimeSpan.FromSeconds(30), startup: true);
            _exit = new AuthorityLifetime(Report).RunAsync(WindowsAuthorityRuntime.Open, _stop.Token).GetAwaiter().GetResult();
        }
        catch { _exit = 70; }
        finally
        {
            lock (_gate)
            {
                if (!_finished && _status != IntPtr.Zero)
                    try { Report(new(AuthorityPhase.Stopped, _exit == 0 ? 70 : _exit)); } catch { _exit = 70; }
                _finished = true;
            }
        }
    }
    private void Report(AuthorityStatus state)
    {
        lock (_gate)
        {
            if (_finished) return;
            if (_stopping && state.Phase == AuthorityPhase.Running) throw new OperationCanceledException();
            if (state.Phase == AuthorityPhase.Running) _running = true;
            if (state.Phase == AuthorityPhase.Stopping && !_stopping)
            { _stopping = true; Watchdog(TimeSpan.FromSeconds(20), startup: false); }
            var pending = state.Phase is AuthorityPhase.Starting or AuthorityPhase.Stopping;
            var status = new Status
            {
                Type = 0x10,
                State = state.Phase switch { AuthorityPhase.Starting => 2u, AuthorityPhase.Running => 4u, AuthorityPhase.Stopping => 3u, _ => 1u },
                Accepted = state.Phase == AuthorityPhase.Running ? 5u : 0,
                Checkpoint = pending ? ++_checkpoint : 0,
                WaitHint = state.Phase == AuthorityPhase.Starting ? 30000u : pending ? 20000u : 0,
                Win32Exit = state.Phase == AuthorityPhase.Stopped && state.ExitCode != 0 ? 1066u : 0,
                ServiceExit = state.Phase == AuthorityPhase.Stopped ? (uint)state.ExitCode : 0,
            };
            if (!SetServiceStatus(_status, ref status)) throw new AuthorityException("AUTHORITY_SCM_STATUS_FAILED");
            if (state.Phase == AuthorityPhase.Stopped) _finished = true;
        }
    }
    private uint Control(uint control, uint eventType, IntPtr data, IntPtr context)
    {
        try
        {
            lock (_gate)
            {
                if (_finished || control == 4) return 0;
                if (control is not (1 or 5)) return 120;
                if (_stopping) return 0;
                Report(new(AuthorityPhase.Stopping, 0));
            }
            ThreadPool.QueueUserWorkItem(_ => { try { _stop.Cancel(); } catch { } });
            return 0;
        }
        catch { return 1064; }
    }
    private void Watchdog(TimeSpan deadline, bool startup)
    {
        _ = Task.Run(async () =>
        {
            await Task.Delay(deadline).ConfigureAwait(false);
            lock (_gate) if (!_finished && (!startup || !_running)) Environment.Exit(71);
        }); // Process exit, not a claim that the Worker/process tree stopped. The durable guard remains for recovery.
    }
    private static string ReadName(IntPtr pointer)
    {
        if (pointer == IntPtr.Zero) throw new AuthorityException("AUTHORITY_SCM_ARGUMENTS_REJECTED");
        var characters = new List<char>();
        for (var i = 0; i <= 64; i++)
        {
            var value = (char)Marshal.ReadInt16(pointer, i * 2);
            if (value == 0) return new string(characters.ToArray()); characters.Add(value);
        }
        throw new AuthorityException("AUTHORITY_SCM_ARGUMENTS_REJECTED");
    }
    public void Dispose() => _stop.Dispose();
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
