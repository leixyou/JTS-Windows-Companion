namespace JTS.WindowsCompanion.Setup;

internal enum CompanionProcessRole
{
    Agent,
    Broker,
}

internal enum CompanionProcessOpenStatus
{
    Opened,
    NotFound,
    AccessDenied,
    Failed,
}

internal readonly record struct CompanionProcessOpenResult<THandle>(
    CompanionProcessOpenStatus Status,
    THandle? Handle,
    int NativeErrorCode)
    where THandle : class, IDisposable
{
    public static CompanionProcessOpenResult<THandle> Opened(THandle handle) =>
        new(CompanionProcessOpenStatus.Opened, handle, 0);

    public static CompanionProcessOpenResult<THandle> Failed(
        CompanionProcessOpenStatus status,
        int nativeErrorCode) =>
        new(status, null, nativeErrorCode);
}

internal interface ICompanionProcessAccess
{
    string CurrentUserSid { get; }

    IReadOnlyList<int> EnumerateProcessIds(string processName);

    CompanionProcessOpenResult<ICompanionProcessQueryHandle> OpenForQuery(int processId);

    CompanionProcessOpenResult<ICompanionProcessStopHandle> OpenForStop(int processId);
}

internal interface ICompanionProcessQueryHandle : IDisposable
{
    int ProcessId { get; }

    bool HasExited { get; }

    string QueryImagePath();

    string QueryOwnerSid();
}

internal interface ICompanionProcessStopHandle : ICompanionProcessQueryHandle
{
    bool RequestClose();

    bool WaitForExit(TimeSpan timeout);

    void Terminate();
}
