using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace JTS.WindowsCompanion.Windows.Elevation;

internal static class WindowsConsentDialog
{
    private const string WindowClassName = "JTS.WindowsCompanion.ElevationConsent.v1";
    private const int ApproveButtonId = 1001;
    private const int CancelButtonId = 1002;
    private static readonly WindowProcedure Procedure = WindowProc;
    private static readonly object RegistrationLock = new();
    private static bool _registered;

    [SupportedOSPlatform("windows")]
    public static bool Show(
        string title,
        string fullText,
        string? instructionText = null,
        string? approveButtonText = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureRegistered();
        var state = new DialogState();
        var stateHandle = GCHandle.Alloc(state);
        try
        {
            var instance = GetModuleHandle(null);
            var screenWidth = GetSystemMetrics(0);
            var screenHeight = GetSystemMetrics(1);
            const int width = 900;
            const int height = 720;
            var window = CreateWindowEx(
                0x00000100,
                WindowClassName,
                title,
                0x00C00000 | 0x00080000 | 0x10000000,
                Math.Max(0, (screenWidth - width) / 2),
                Math.Max(0, (screenHeight - height) / 2),
                width,
                height,
                IntPtr.Zero,
                IntPtr.Zero,
                instance,
                GCHandle.ToIntPtr(stateHandle));
            if (window == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            state.AttachWindow(window);
            using var cancellationRegistration = cancellationToken.Register(
                static value => ((DialogState)value!).Cancel(),
                state);

            var font = GetStockObject(17);
            var instructions = CreateWindowEx(
                0,
                "STATIC",
                instructionText
                    ?? "Review every line below. Approve only if the complete script, directory, duration, and data scopes are correct.",
                0x50000000,
                20,
                18,
                840,
                42,
                window,
                IntPtr.Zero,
                instance,
                IntPtr.Zero);
            var details = CreateWindowEx(
                0x00000200,
                "EDIT",
                string.Empty,
                0x50000000 | 0x00800000 | 0x00200000 | 0x00100000 | 0x00000004 | 0x00000040 | 0x00000800 | 0x00000080,
                20,
                66,
                840,
                550,
                window,
                IntPtr.Zero,
                instance,
                IntPtr.Zero);
            var approve = CreateWindowEx(
                0,
                "BUTTON",
                approveButtonText ?? "Approve and open Windows UAC",
                0x50010000 | 0x00000001,
                510,
                632,
                220,
                36,
                window,
                new IntPtr(ApproveButtonId),
                instance,
                IntPtr.Zero);
            var cancel = CreateWindowEx(
                0,
                "BUTTON",
                "Cancel",
                0x50010000,
                740,
                632,
                120,
                36,
                window,
                new IntPtr(CancelButtonId),
                instance,
                IntPtr.Zero);
            if (instructions == IntPtr.Zero || details == IntPtr.Zero || approve == IntPtr.Zero || cancel == IntPtr.Zero)
            {
                _ = DestroyWindow(window);
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            foreach (var control in new[] { instructions, details, approve, cancel })
            {
                _ = SendMessage(control, 0x0030, font, new IntPtr(1));
            }

            if (fullText.Length > 128 * 1024)
            {
                _ = DestroyWindow(window);
                throw new InvalidOperationException("The complete elevation consent text exceeds its display bound.");
            }

            _ = SendMessage(details, 0x00C5, new IntPtr(128 * 1024), IntPtr.Zero);
            if (!SetWindowText(details, fullText))
            {
                _ = DestroyWindow(window);
                throw new InvalidOperationException("The complete elevation consent text could not be displayed.");
            }

            _ = SendMessage(details, 0x00B1, IntPtr.Zero, IntPtr.Zero);
            _ = ShowWindow(window, 5);
            _ = SetForegroundWindow(window);
            _ = UpdateWindow(window);
            while (true)
            {
                var result = GetMessage(out var message, IntPtr.Zero, 0, 0);
                if (result == -1)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                if (result == 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    return state.Approved;
                }

                _ = TranslateMessage(ref message);
                _ = DispatchMessage(ref message);
            }
        }
        finally
        {
            if (stateHandle.IsAllocated)
            {
                stateHandle.Free();
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static void EnsureRegistered()
    {
        lock (RegistrationLock)
        {
            if (_registered)
            {
                return;
            }

            var instance = GetModuleHandle(null);
            var windowClass = new WindowClass
            {
                Size = (uint)Marshal.SizeOf<WindowClass>(),
                Procedure = Procedure,
                Instance = instance,
                Cursor = LoadCursor(IntPtr.Zero, new IntPtr(32512)),
                Background = new IntPtr(6),
                ClassName = WindowClassName,
            };
            if (RegisterClassEx(ref windowClass) == 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            _registered = true;
        }
    }

    private static IntPtr WindowProc(IntPtr window, uint message, IntPtr wordParameter, IntPtr longParameter)
    {
        if (message == 0x0081)
        {
            var create = Marshal.PtrToStructure<CreateStructure>(longParameter);
            _ = SetWindowLongPtr(window, -21, create.CreateParameters);
        }

        var statePointer = GetWindowLongPtr(window, -21);
        var state = statePointer == IntPtr.Zero
            ? null
            : GCHandle.FromIntPtr(statePointer).Target as DialogState;
        switch (message)
        {
            case 0x0111:
                var commandId = unchecked((ushort)wordParameter.ToInt64());
                if (commandId is ApproveButtonId or CancelButtonId)
                {
                    if (state is not null)
                    {
                        state.Approved = commandId == ApproveButtonId;
                    }

                    _ = DestroyWindow(window);
                    return IntPtr.Zero;
                }

                break;
            case 0x0010:
                if (state is not null)
                {
                    state.Approved = false;
                }

                _ = DestroyWindow(window);
                return IntPtr.Zero;
            case 0x0002:
                state?.DetachWindow(window);
                PostQuitMessage(0);
                return IntPtr.Zero;
        }

        return DefWindowProc(window, message, wordParameter, longParameter);
    }

    private sealed class DialogState
    {
        private IntPtr _window;
        private int _cancelled;

        public bool Approved { get; set; }

        public void AttachWindow(IntPtr window)
        {
            _ = Interlocked.Exchange(ref _window, window);
            if (Volatile.Read(ref _cancelled) != 0)
            {
                _ = PostMessage(window, 0x0010, IntPtr.Zero, IntPtr.Zero);
            }
        }

        public void DetachWindow(IntPtr window)
        {
            _ = Interlocked.CompareExchange(ref _window, IntPtr.Zero, window);
        }

        public void Cancel()
        {
            _ = Interlocked.Exchange(ref _cancelled, 1);
            var window = Interlocked.CompareExchange(ref _window, IntPtr.Zero, IntPtr.Zero);
            if (window != IntPtr.Zero)
            {
                _ = PostMessage(window, 0x0010, IntPtr.Zero, IntPtr.Zero);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WindowClass
    {
        public uint Size;
        public uint Style;
        public WindowProcedure? Procedure;
        public int ClassExtra;
        public int WindowExtra;
        public IntPtr Instance;
        public IntPtr Icon;
        public IntPtr Cursor;
        public IntPtr Background;

        [MarshalAs(UnmanagedType.LPWStr)]
        public string? MenuName;

        [MarshalAs(UnmanagedType.LPWStr)]
        public string? ClassName;

        public IntPtr SmallIcon;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CreateStructure
    {
        public IntPtr CreateParameters;
        public IntPtr Instance;
        public IntPtr Menu;
        public IntPtr Parent;
        public int Height;
        public int Width;
        public int Y;
        public int X;
        public int Style;
        public IntPtr Name;
        public IntPtr Class;
        public uint ExtendedStyle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Message
    {
        public IntPtr Window;
        public uint Value;
        public UIntPtr WordParameter;
        public IntPtr LongParameter;
        public uint Time;
        public int PointX;
        public int PointY;
        public uint Private;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate IntPtr WindowProcedure(IntPtr window, uint message, IntPtr wordParameter, IntPtr longParameter);

    [DllImport("kernel32.dll", EntryPoint = "GetModuleHandleW", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandle(string? moduleName);

    [DllImport("user32.dll", EntryPoint = "RegisterClassExW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ushort RegisterClassEx(ref WindowClass windowClass);

    [DllImport("user32.dll", EntryPoint = "CreateWindowExW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateWindowEx(
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
    private static extern IntPtr DefWindowProc(IntPtr window, uint message, IntPtr wordParameter, IntPtr longParameter);

    [DllImport("user32.dll", EntryPoint = "PostMessageW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostMessage(IntPtr window, uint message, IntPtr wordParameter, IntPtr longParameter);

    [DllImport("user32.dll", EntryPoint = "SetWindowLongPtrW")]
    private static extern IntPtr SetWindowLongPtr(IntPtr window, int index, IntPtr newValue);

    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW")]
    private static extern IntPtr GetWindowLongPtr(IntPtr window, int index);

    [DllImport("user32.dll", EntryPoint = "GetMessageW", SetLastError = true)]
    private static extern int GetMessage(out Message message, IntPtr window, uint minimum, uint maximum);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TranslateMessage([In] ref Message message);

    [DllImport("user32.dll", EntryPoint = "DispatchMessageW")]
    private static extern IntPtr DispatchMessage([In] ref Message message);

    [DllImport("user32.dll")]
    private static extern void PostQuitMessage(int exitCode);

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int index);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindow(IntPtr window, int command);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateWindow(IntPtr window);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(IntPtr window);

    [DllImport("user32.dll")]
    private static extern IntPtr LoadCursor(IntPtr instance, IntPtr cursorName);

    [DllImport("gdi32.dll")]
    private static extern IntPtr GetStockObject(int objectIndex);

    [DllImport("user32.dll", EntryPoint = "SendMessageW")]
    private static extern IntPtr SendMessage(IntPtr window, uint message, IntPtr wordParameter, IntPtr longParameter);

    [DllImport("user32.dll", EntryPoint = "SetWindowTextW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowText(IntPtr window, string text);

}
