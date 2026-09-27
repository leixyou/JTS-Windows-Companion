using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace JTS.WindowsCompanion.Setup;

internal sealed class WindowsCompanionProcessAccess : ICompanionProcessAccess
{
    public string CurrentUserSid
    {
        get
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException("Companion process control is available only on Windows.");
            }
            return CurrentUserSidWindows();
        }
    }

    public IReadOnlyList<int> EnumerateProcessIds(string processName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(processName);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Companion process control is available only on Windows.");
        }
        return EnumerateProcessIdsWindows(processName);
    }

    public CompanionProcessOpenResult<ICompanionProcessQueryHandle> OpenForQuery(int processId)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Companion process control is available only on Windows.");
        }
        return OpenWindows<ICompanionProcessQueryHandle>(
            processId,
            ProcessQueryLimitedInformation,
            static (handle, id) => new WindowsCompanionProcessHandle(handle, id));
    }

    public CompanionProcessOpenResult<ICompanionProcessStopHandle> OpenForStop(int processId)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Companion process control is available only on Windows.");
        }
        return OpenWindows<ICompanionProcessStopHandle>(
            processId,
            ProcessQueryLimitedInformation | ProcessTerminate | Synchronize,
            static (handle, id) => new WindowsCompanionProcessHandle(handle, id));
    }

    [SupportedOSPlatform("windows")]
    private static string CurrentUserSidWindows()
    {
        using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        return identity.User?.Value
            ?? throw new UnauthorizedAccessException("The current Windows user SID is unavailable.");
    }

    private static IReadOnlyList<int> EnumerateProcessIdsWindows(string processName)
    {
        var processes = Process.GetProcessesByName(processName);
        try
        {
            var processIds = new List<int>(processes.Length);
            foreach (var process in processes)
            {
                try
                {
                    processIds.Add(process.Id);
                }
                catch (InvalidOperationException)
                {
                    // The process exited between the system snapshot and reading its PID.
                }
            }
            return processIds;
        }
        finally
        {
            foreach (var process in processes)
            {
                process.Dispose();
            }
        }
    }

    private static CompanionProcessOpenResult<THandle> OpenWindows<THandle>(
        int processId,
        uint desiredAccess,
        Func<SafeProcessHandle, int, THandle> createHandle)
        where THandle : class, IDisposable
    {
        if (processId <= 0)
        {
            return CompanionProcessOpenResult<THandle>.Failed(
                CompanionProcessOpenStatus.NotFound,
                ErrorInvalidParameter);
        }

        var nativeHandle = OpenProcessNative(desiredAccess, inheritHandle: false, checked((uint)processId));
        if (!nativeHandle.IsInvalid)
        {
            return CompanionProcessOpenResult<THandle>.Opened(createHandle(nativeHandle, processId));
        }

        var error = Marshal.GetLastWin32Error();
        nativeHandle.Dispose();
        var status = error switch
        {
            ErrorAccessDenied => CompanionProcessOpenStatus.AccessDenied,
            ErrorInvalidParameter or ErrorNotFound => CompanionProcessOpenStatus.NotFound,
            _ => CompanionProcessOpenStatus.Failed,
        };
        return CompanionProcessOpenResult<THandle>.Failed(status, error);
    }

    private const uint ProcessTerminate = 0x0001;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint Synchronize = 0x00100000;
    private const int ErrorAccessDenied = 5;
    private const int ErrorInvalidParameter = 87;
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorNotFound = 1168;
    private const uint TokenQuery = 0x0008;
    private const uint StillActive = 259;
    private const uint WaitObject0 = 0;
    private const uint WaitTimeout = 258;
    private const uint WaitFailed = 0xFFFFFFFF;
    private const uint WmClose = 0x0010;

    private sealed class WindowsCompanionProcessHandle : ICompanionProcessStopHandle
    {
        private readonly SafeProcessHandle _handle;

        public WindowsCompanionProcessHandle(SafeProcessHandle handle, int processId)
        {
            _handle = handle;
            ProcessId = processId;
        }

        public int ProcessId { get; }

        public bool HasExited
        {
            get
            {
                if (!GetExitCodeProcess(_handle, out var exitCode))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                return exitCode != StillActive;
            }
        }

        public string QueryImagePath()
        {
            var capacity = 32_768;
            var buffer = new char[capacity];
            if (!QueryFullProcessImageName(_handle, 0, buffer, ref capacity) || capacity <= 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return new string(buffer, 0, capacity);
        }

        public string QueryOwnerSid()
        {
            if (!OpenProcessToken(_handle, TokenQuery, out var token))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            using (token)
            {
                var buffer = QueryTokenUserBuffer(token);
                try
                {
                    var tokenUser = Marshal.PtrToStructure<TokenUser>(buffer);
                    return ConvertSidToString(tokenUser.User.Sid);
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }

        public bool RequestClose()
        {
            var closeRequested = false;
            EnumWindowsProc callback = (window, parameter) =>
            {
                _ = parameter;
                _ = GetWindowThreadProcessId(window, out var ownerProcessId);
                if (ownerProcessId == checked((uint)ProcessId)
                    && PostMessage(window, WmClose, IntPtr.Zero, IntPtr.Zero))
                {
                    closeRequested = true;
                }
                return true;
            };
            if (!EnumWindows(callback, IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            GC.KeepAlive(callback);
            return closeRequested;
        }

        public bool WaitForExit(TimeSpan timeout)
        {
            if (timeout < TimeSpan.Zero && timeout != Timeout.InfiniteTimeSpan)
            {
                throw new ArgumentOutOfRangeException(nameof(timeout));
            }
            var milliseconds = timeout == Timeout.InfiniteTimeSpan
                ? uint.MaxValue
                : checked((uint)Math.Min(uint.MaxValue - 1, Math.Ceiling(timeout.TotalMilliseconds)));
            var result = WaitForSingleObject(_handle, milliseconds);
            return result switch
            {
                WaitObject0 => true,
                WaitTimeout => false,
                WaitFailed => throw new Win32Exception(Marshal.GetLastWin32Error()),
                _ => throw new InvalidOperationException("The Windows process wait returned an unexpected result."),
            };
        }

        public void Terminate()
        {
            if (HasExited)
            {
                return;
            }
            if (TerminateProcess(_handle, 1))
            {
                return;
            }

            var error = Marshal.GetLastWin32Error();
            if (!HasExited)
            {
                throw new Win32Exception(error);
            }
        }

        public void Dispose() => _handle.Dispose();

        private static IntPtr QueryTokenUserBuffer(SafeAccessTokenHandle token)
        {
            _ = GetTokenInformation(
                token,
                TokenInformationClass.User,
                IntPtr.Zero,
                0,
                out var requiredSize);
            var error = Marshal.GetLastWin32Error();
            if (requiredSize == 0 || error != ErrorInsufficientBuffer)
            {
                throw new Win32Exception(error);
            }

            var buffer = Marshal.AllocHGlobal(checked((int)requiredSize));
            if (GetTokenInformation(
                    token,
                    TokenInformationClass.User,
                    buffer,
                    requiredSize,
                    out _))
            {
                return buffer;
            }

            error = Marshal.GetLastWin32Error();
            Marshal.FreeHGlobal(buffer);
            throw new Win32Exception(error);
        }

        private static string ConvertSidToString(IntPtr sid)
        {
            if (sid == IntPtr.Zero || !ConvertSidToStringSid(sid, out var stringSid))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            try
            {
                return Marshal.PtrToStringUni(stringSid)
                    ?? throw new UnauthorizedAccessException("The process owner SID is unavailable.");
            }
            finally
            {
                _ = LocalFree(stringSid);
            }
        }
    }

    private enum TokenInformationClass
    {
        User = 1,
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenUser
    {
        public SidAndAttributes User;
    }

    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool EnumWindowsProc(IntPtr window, IntPtr parameter);

    [DllImport("kernel32.dll", EntryPoint = "OpenProcess", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcessNative(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint processId);

    [DllImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(
        SafeProcessHandle process,
        uint flags,
        [Out] char[] executableName,
        ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(
        SafeProcessHandle process,
        out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(
        SafeProcessHandle process,
        uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(
        SafeProcessHandle process,
        uint exitCode);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        SafeProcessHandle process,
        uint desiredAccess,
        out SafeAccessTokenHandle token);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        SafeAccessTokenHandle token,
        TokenInformationClass tokenInformationClass,
        IntPtr tokenInformation,
        uint tokenInformationLength,
        out uint returnLength);

    [DllImport("advapi32.dll", EntryPoint = "ConvertSidToStringSidW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr stringSid);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(
        EnumWindowsProc callback,
        IntPtr parameter);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint GetWindowThreadProcessId(
        IntPtr window,
        out uint processId);

    [DllImport("user32.dll", EntryPoint = "PostMessageW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostMessage(
        IntPtr window,
        uint message,
        IntPtr wParam,
        IntPtr lParam);
}
