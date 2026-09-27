using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace JTS.WindowsCompanion.Windows.Managed;

public sealed class WindowsManagedServiceProcessIdentitySource : IManagedServiceProcessIdentitySource
{
    public ManagedServiceProcessIdentity Capture(string registeredServiceName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(registeredServiceName);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Managed service process identity discovery is available only on Windows.");
        }

        return CaptureWindows(registeredServiceName);
    }

    [SupportedOSPlatform("windows")]
    private static ManagedServiceProcessIdentity CaptureWindows(string registeredServiceName)
    {
        using var manager = OpenSCManager(null, null, ScManagerConnect);
        if (manager.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        using var service = OpenService(
            manager,
            registeredServiceName,
            ServiceQueryConfig | ServiceQueryStatus);
        if (service.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        var status = QueryStatus(service);
        var configuration = QueryConfiguration(service);
        var processId = checked((int)status.ProcessId);
        if (processId <= 0)
        {
            throw new UnauthorizedAccessException("The registered managed service is not running.");
        }

        using var process = OpenProcess(ProcessQueryLimitedInformation, false, status.ProcessId);
        if (process.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        var processPath = QueryProcessPath(process);
        if (!OpenProcessToken(process, TokenQuery, out var token))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        using (token)
        {
            var userSid = QueryTokenUserSid(token);
            var tokenGroups = QueryTokenGroups(token);
            if (!ProcessIdToSessionId(status.ProcessId, out var sessionId))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return new ManagedServiceProcessIdentity(
                registeredServiceName,
                processId,
                configuration.BinaryPathName,
                configuration.ServiceStartName,
                status.ServiceType == ServiceWin32OwnProcess
                    && configuration.ServiceType == ServiceWin32OwnProcess,
                Enum.IsDefined(typeof(ManagedServiceScmState), status.CurrentState)
                    ? (ManagedServiceScmState)status.CurrentState
                    : ManagedServiceScmState.Unknown,
                processId,
                processPath,
                userSid,
                checked((int)sessionId),
                tokenGroups.All.Contains(InteractiveSid),
                tokenGroups.Enabled.Contains(ServiceSid));
        }
    }

    [SupportedOSPlatform("windows")]
    private static ServiceStatusProcess QueryStatus(SafeServiceHandle service)
    {
        var size = (uint)Marshal.SizeOf<ServiceStatusProcess>();
        var buffer = Marshal.AllocHGlobal(checked((int)size));
        try
        {
            if (!QueryServiceStatusEx(service, ScStatusProcessInfo, buffer, size, out _))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return Marshal.PtrToStructure<ServiceStatusProcess>(buffer);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [SupportedOSPlatform("windows")]
    private static ServiceConfiguration QueryConfiguration(SafeServiceHandle service)
    {
        _ = QueryServiceConfig(service, IntPtr.Zero, 0, out var requiredSize);
        var error = Marshal.GetLastWin32Error();
        if (requiredSize == 0 || error != ErrorInsufficientBuffer)
        {
            throw new Win32Exception(error);
        }

        var buffer = Marshal.AllocHGlobal(checked((int)requiredSize));
        try
        {
            if (!QueryServiceConfig(service, buffer, requiredSize, out _))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var native = Marshal.PtrToStructure<QueryServiceConfigResult>(buffer);
            return new ServiceConfiguration(
                native.ServiceType,
                Marshal.PtrToStringUni(native.BinaryPathName),
                Marshal.PtrToStringUni(native.ServiceStartName));
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [SupportedOSPlatform("windows")]
    private static string QueryProcessPath(SafeProcessHandle process)
    {
        var capacity = 32_768;
        var buffer = new char[capacity];
        if (!QueryFullProcessImageName(process, 0, buffer, ref capacity) || capacity <= 0)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        return new string(buffer, 0, capacity);
    }

    [SupportedOSPlatform("windows")]
    private static string QueryTokenUserSid(SafeAccessTokenHandle token)
    {
        var buffer = QueryTokenInformationBuffer(token, TokenInformationClass.User);
        try
        {
            var user = Marshal.PtrToStructure<TokenUser>(buffer);
            return ConvertSidToString(user.User.Sid);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [SupportedOSPlatform("windows")]
    private static TokenGroupMembership QueryTokenGroups(SafeAccessTokenHandle token)
    {
        var buffer = QueryTokenInformationBuffer(token, TokenInformationClass.Groups);
        try
        {
            var groupCount = checked((uint)Marshal.ReadInt32(buffer));
            var groupOffset = Marshal.OffsetOf<TokenGroups>(nameof(TokenGroups.Groups)).ToInt32();
            var entrySize = Marshal.SizeOf<SidAndAttributes>();
            var allGroups = new HashSet<string>(StringComparer.Ordinal);
            var enabledGroups = new HashSet<string>(StringComparer.Ordinal);
            for (var index = 0U; index < groupCount; index++)
            {
                var entry = Marshal.PtrToStructure<SidAndAttributes>(
                    IntPtr.Add(buffer, checked(groupOffset + (int)index * entrySize)));
                var sid = ConvertSidToString(entry.Sid);
                allGroups.Add(sid);
                if ((entry.Attributes & SeGroupEnabled) != 0
                    && (entry.Attributes & SeGroupUseForDenyOnly) == 0)
                {
                    enabledGroups.Add(sid);
                }
            }

            return new TokenGroupMembership(allGroups, enabledGroups);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [SupportedOSPlatform("windows")]
    private static IntPtr QueryTokenInformationBuffer(
        SafeAccessTokenHandle token,
        TokenInformationClass informationClass)
    {
        _ = GetTokenInformation(token, informationClass, IntPtr.Zero, 0, out var requiredSize);
        var error = Marshal.GetLastWin32Error();
        if (requiredSize == 0 || error != ErrorInsufficientBuffer)
        {
            throw new Win32Exception(error);
        }

        var buffer = Marshal.AllocHGlobal(checked((int)requiredSize));
        if (GetTokenInformation(token, informationClass, buffer, requiredSize, out _))
        {
            return buffer;
        }

        error = Marshal.GetLastWin32Error();
        Marshal.FreeHGlobal(buffer);
        throw new Win32Exception(error);
    }

    [SupportedOSPlatform("windows")]
    private static string ConvertSidToString(IntPtr sid)
    {
        if (sid == IntPtr.Zero || !ConvertSidToStringSid(sid, out var stringSid))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        try
        {
            return Marshal.PtrToStringUni(stringSid)
                ?? throw new UnauthorizedAccessException("A managed service token SID is unavailable.");
        }
        finally
        {
            _ = LocalFree(stringSid);
        }
    }

    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryConfig = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const int ScStatusProcessInfo = 0;
    private const uint ServiceWin32OwnProcess = 0x00000010;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;
    private const uint SeGroupEnabled = 0x00000004;
    private const uint SeGroupUseForDenyOnly = 0x00000010;
    private const int ErrorInsufficientBuffer = 122;
    private const string InteractiveSid = "S-1-5-4";
    private const string ServiceSid = "S-1-5-6";

    private sealed record ServiceConfiguration(
        uint ServiceType,
        string? BinaryPathName,
        string? ServiceStartName);

    private sealed record TokenGroupMembership(
        IReadOnlySet<string> All,
        IReadOnlySet<string> Enabled);

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct QueryServiceConfigResult
    {
        public uint ServiceType;
        public uint StartType;
        public uint ErrorControl;
        public IntPtr BinaryPathName;
        public IntPtr LoadOrderGroup;
        public uint TagId;
        public IntPtr Dependencies;
        public IntPtr ServiceStartName;
        public IntPtr DisplayName;
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

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenGroups
    {
        public uint GroupCount;
        public SidAndAttributes Groups;
    }

    private enum TokenInformationClass
    {
        User = 1,
        Groups = 2,
    }

    private sealed class SafeServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeServiceHandle()
            : base(ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }

    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeServiceHandle OpenSCManager(
        string? machineName,
        string? databaseName,
        uint desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeServiceHandle OpenService(
        SafeServiceHandle serviceControlManager,
        string serviceName,
        uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr serviceHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(
        SafeServiceHandle service,
        int informationLevel,
        IntPtr buffer,
        uint bufferSize,
        out uint bytesNeeded);

    [DllImport("advapi32.dll", EntryPoint = "QueryServiceConfigW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfig(
        SafeServiceHandle service,
        IntPtr serviceConfig,
        uint bufferSize,
        out uint bytesNeeded);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(
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

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ProcessIdToSessionId(uint processId, out uint sessionId);
}
