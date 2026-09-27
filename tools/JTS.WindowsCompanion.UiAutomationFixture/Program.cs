using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace JTS.WindowsCompanion.UiAutomationFixture;

internal static class Program
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    [STAThread]
    public static async Task<int> Main(string[] arguments)
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10))
        {
            return 2;
        }

        try
        {
            var pipeName = ParsePipeName(arguments);
            using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
            await RunAsync(pipeName, deadline.Token).ConfigureAwait(false);
            return 0;
        }
        catch
        {
            return 1;
        }
    }

    private static async Task RunAsync(string pipeName, CancellationToken cancellationToken)
    {
        await using var pipe = new NamedPipeClientStream(
            ".",
            pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous);
        await pipe.ConnectAsync(30_000, cancellationToken).ConfigureAwait(false);
        await using var fixture = await FixtureWindow.StartAsync(cancellationToken)
            .ConfigureAwait(false);
        using var reader = new StreamReader(
            pipe,
            new UTF8Encoding(false, true),
            detectEncodingFromByteOrderMarks: false,
            bufferSize: 4_096,
            leaveOpen: true);
        using var writer = new StreamWriter(
            pipe,
            new UTF8Encoding(false, true),
            bufferSize: 4_096,
            leaveOpen: true)
        {
            AutoFlush = true,
        };

        await WriteAsync(
                writer,
                new FixtureResponse(
                    true,
                    null,
                    fixture.WindowName,
                    fixture.EditorName,
                    fixture.ButtonName,
                    Environment.ProcessId,
                    null,
                    1),
                cancellationToken)
            .ConfigureAwait(false);

        while (true)
        {
            var request = await ReadRequestAsync(reader, cancellationToken).ConfigureAwait(false);
            switch (request.Command)
            {
                case "read":
                    await WriteAsync(
                            writer,
                            FixtureResponse.Success(value: fixture.ReadEditorValue()),
                            cancellationToken)
                        .ConfigureAwait(false);
                    break;
                case "waitInvoke":
                    await fixture.WaitForInvokeAsync(cancellationToken).ConfigureAwait(false);
                    await WriteAsync(writer, FixtureResponse.Success(), cancellationToken)
                        .ConfigureAwait(false);
                    break;
                case "close":
                    await WriteAsync(writer, FixtureResponse.Success(), cancellationToken)
                        .ConfigureAwait(false);
                    return;
                default:
                    await WriteAsync(
                            writer,
                            FixtureResponse.Failure("The fixture command is unsupported."),
                            cancellationToken)
                        .ConfigureAwait(false);
                    break;
            }
        }
    }

    private static string ParsePipeName(string[] arguments)
    {
        if (arguments.Length != 2
            || !string.Equals(arguments[0], "--pipe", StringComparison.Ordinal)
            || arguments[1].Length is < 1 or > 128
            || !arguments[1].All(character =>
                char.IsAsciiLetterOrDigit(character) || character is '.' or '-'))
        {
            throw new ArgumentException("The fixture pipe argument is invalid.");
        }

        return arguments[1];
    }

    private static async ValueTask<FixtureRequest> ReadRequestAsync(
        StreamReader reader,
        CancellationToken cancellationToken)
    {
        var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new EndOfStreamException("The fixture controller disconnected.");
        if (line.Length is < 1 or > 4_096)
        {
            throw new InvalidDataException("The fixture command length is invalid.");
        }

        return JsonSerializer.Deserialize<FixtureRequest>(line, JsonOptions)
            ?? throw new InvalidDataException("The fixture command is missing.");
    }

    private static async ValueTask WriteAsync(
        StreamWriter writer,
        FixtureResponse response,
        CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(response, JsonOptions);
        await writer.WriteLineAsync(json.AsMemory(), cancellationToken).ConfigureAwait(false);
    }

    private sealed record FixtureRequest(string Command);

    private sealed record FixtureResponse(
        bool Ok,
        string? Error,
        string? WindowName,
        string? EditorName,
        string? ButtonName,
        int? ProcessId,
        string? Value,
        int? SchemaVersion)
    {
        public static FixtureResponse Success(string? value = null) =>
            new(true, null, null, null, null, null, value, 1);

        public static FixtureResponse Failure(string error) =>
            new(false, error, null, null, null, null, null, 1);
    }
}

[SupportedOSPlatform("windows10.0")]
internal sealed class FixtureWindow : IAsyncDisposable
{
    private const int EditorControlId = 10_001;
    private const int InvokeControlId = 10_002;
    private const uint WmClose = 0x0010;
    private const uint WmDestroy = 0x0002;
    private const uint WmCommand = 0x0111;
    private const uint WsOverlappedWindow = 0x00CF0000;
    private const uint WsVisible = 0x10000000;
    private const uint WsChild = 0x40000000;
    private const uint WsBorder = 0x00800000;
    private const uint EsAutoHScroll = 0x0080;
    private const int SwShow = 5;

    private readonly TaskCompletionSource _ready =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _invoked =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _stopped =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly WindowProcedure _windowProcedure;
    private readonly Thread _thread;
    private IntPtr _window;
    private IntPtr _editor;
    private int _disposed;

    private FixtureWindow()
    {
        var suffix = Guid.NewGuid().ToString("N");
        ClassName = $"JTS.WindowsCompanion.UiAutomationFixture.{suffix}";
        WindowName = $"JTS UIA Fixture {suffix}";
        EditorName = $"JTS UIA Editor {suffix}";
        ButtonName = $"JTS UIA Invoke {suffix}";
        _windowProcedure = HandleWindowMessage;
        _thread = new Thread(RunMessageLoop)
        {
            IsBackground = true,
            Name = "JTS UI Automation fixture window",
        };
        _thread.SetApartmentState(ApartmentState.STA);
    }

    public string ClassName { get; }

    public string WindowName { get; }

    public string EditorName { get; }

    public string ButtonName { get; }

    public static async ValueTask<FixtureWindow> StartAsync(
        CancellationToken cancellationToken)
    {
        var fixture = new FixtureWindow();
        fixture._thread.Start();
        try
        {
            await fixture._ready.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            return fixture;
        }
        catch
        {
            await fixture.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public async ValueTask WaitForInvokeAsync(CancellationToken cancellationToken) =>
        await _invoked.Task.WaitAsync(cancellationToken).ConfigureAwait(false);

    public string ReadEditorValue()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        var length = GetWindowTextLengthW(_editor);
        var value = new StringBuilder(length + 1);
        if (GetWindowTextW(_editor, value, value.Capacity) == 0 && length != 0)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        return value.ToString();
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        var window = Volatile.Read(ref _window);
        if (window != IntPtr.Zero && !PostMessageW(window, WmClose, IntPtr.Zero, IntPtr.Zero))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        await _stopped.Task.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
    }

    private void RunMessageLoop()
    {
        var instance = GetModuleHandleW(null);
        ushort classAtom = 0;
        try
        {
            var windowClass = new WindowClass
            {
                Instance = instance,
                ClassName = ClassName,
                WindowProcedure = _windowProcedure,
            };
            classAtom = RegisterClassW(ref windowClass);
            if (classAtom == 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            _window = CreateWindowExW(
                0,
                ClassName,
                WindowName,
                WsOverlappedWindow | WsVisible,
                100,
                100,
                520,
                180,
                IntPtr.Zero,
                IntPtr.Zero,
                instance,
                IntPtr.Zero);
            if (_window == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            _editor = CreateWindowExW(
                0,
                "EDIT",
                EditorName,
                WsChild | WsVisible | WsBorder | EsAutoHScroll,
                20,
                25,
                460,
                32,
                _window,
                new IntPtr(EditorControlId),
                instance,
                IntPtr.Zero);
            var button = CreateWindowExW(
                0,
                "BUTTON",
                ButtonName,
                WsChild | WsVisible,
                20,
                75,
                180,
                34,
                _window,
                new IntPtr(InvokeControlId),
                instance,
                IntPtr.Zero);
            if (_editor == IntPtr.Zero || button == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            _ = ShowWindow(_window, SwShow);
            if (!UpdateWindow(_window))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            _ready.TrySetResult();
            while (true)
            {
                var result = GetMessageW(out var message, IntPtr.Zero, 0, 0);
                if (result == 0)
                {
                    break;
                }

                if (result == -1)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                _ = TranslateMessage(ref message);
                _ = DispatchMessageW(ref message);
            }
        }
        catch (Exception exception)
        {
            _ready.TrySetException(exception);
        }
        finally
        {
            var window = Interlocked.Exchange(ref _window, IntPtr.Zero);
            if (window != IntPtr.Zero && IsWindow(window))
            {
                _ = DestroyWindow(window);
            }

            if (classAtom != 0)
            {
                _ = UnregisterClassW(ClassName, instance);
            }

            _stopped.TrySetResult();
        }
    }

    private IntPtr HandleWindowMessage(
        IntPtr window,
        uint message,
        IntPtr wParam,
        IntPtr lParam)
    {
        if (message == WmCommand && (wParam.ToInt64() & 0xFFFF) == InvokeControlId)
        {
            _invoked.TrySetResult();
            return IntPtr.Zero;
        }

        if (message == WmClose)
        {
            _ = DestroyWindow(window);
            return IntPtr.Zero;
        }

        if (message == WmDestroy)
        {
            PostQuitMessage(0);
            return IntPtr.Zero;
        }

        return DefWindowProcW(window, message, wParam, lParam);
    }

    private delegate IntPtr WindowProcedure(
        IntPtr window,
        uint message,
        IntPtr wParam,
        IntPtr lParam);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WindowClass
    {
        public uint Style;
        public WindowProcedure WindowProcedure;
        public int ClassExtraBytes;
        public int WindowExtraBytes;
        public IntPtr Instance;
        public IntPtr Icon;
        public IntPtr Cursor;
        public IntPtr BackgroundBrush;
        public string? MenuName;
        public string ClassName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeMessage
    {
        public IntPtr Window;
        public uint Message;
        public IntPtr WParam;
        public IntPtr LParam;
        public uint Time;
        public int PointX;
        public int PointY;
        public uint Private;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandleW(string? moduleName);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ushort RegisterClassW(ref WindowClass windowClass);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnregisterClassW(string className, IntPtr instance);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateWindowExW(
        uint extendedStyle,
        string className,
        string windowName,
        uint style,
        int x,
        int y,
        int width,
        int height,
        IntPtr parent,
        IntPtr menu,
        IntPtr instance,
        IntPtr parameter);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyWindow(IntPtr window);

    [DllImport("user32.dll")]
    private static extern IntPtr DefWindowProcW(
        IntPtr window,
        uint message,
        IntPtr wParam,
        IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern void PostQuitMessage(int exitCode);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int GetMessageW(
        out NativeMessage message,
        IntPtr window,
        uint minimumMessage,
        uint maximumMessage);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TranslateMessage(ref NativeMessage message);

    [DllImport("user32.dll")]
    private static extern IntPtr DispatchMessageW(ref NativeMessage message);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindow(IntPtr window, int command);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateWindow(IntPtr window);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostMessageW(
        IntPtr window,
        uint message,
        IntPtr wParam,
        IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindow(IntPtr window);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetWindowTextLengthW(IntPtr window);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetWindowTextW(
        IntPtr window,
        StringBuilder value,
        int maximumCharacters);
}
