using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace JTS.WindowsCompanion.Elevation;

internal interface IContainedProcessFactory
{
    IContainedProcess Create(ProcessStartInfo startInfo);
}

internal interface IContainedProcess : IAsyncDisposable
{
    TextReader StandardOutput { get; }

    TextReader StandardError { get; }

    bool HasExited { get; }

    int ExitCode { get; }

    ValueTask StartAsync(CancellationToken cancellationToken);

    ValueTask WriteStandardInputAsync(ReadOnlyMemory<char> text, CancellationToken cancellationToken);

    Task WaitForExitAsync(CancellationToken cancellationToken);

    ValueTask TerminateAsync();
}

internal sealed class WindowsJobObjectProcessFactory : IContainedProcessFactory
{
    public static WindowsJobObjectProcessFactory Instance { get; } = new();

    private WindowsJobObjectProcessFactory()
    {
    }

    public IContainedProcess Create(ProcessStartInfo startInfo)
    {
        ArgumentNullException.ThrowIfNull(startInfo);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Elevated processes require Windows Job Object containment.");
        }

        return new WindowsJobObjectProcess(startInfo);
    }
}

internal sealed class WindowsJobObjectProcess : IContainedProcess
{
    private static readonly TimeSpan TerminationTimeout = TimeSpan.FromSeconds(5);
    private readonly Process _process;
    private SafeFileHandle? _job;
    private bool _started;
    private bool _disposed;

    public WindowsJobObjectProcess(ProcessStartInfo startInfo)
    {
        _process = new Process { StartInfo = startInfo };
    }

    public TextReader StandardOutput => _process.StandardOutput;

    public TextReader StandardError => _process.StandardError;

    public bool HasExited
    {
        get
        {
            if (!_started)
            {
                return false;
            }

            try
            {
                return _process.HasExited;
            }
            catch (InvalidOperationException)
            {
                return true;
            }
        }
    }

    public int ExitCode => _process.ExitCode;

    public ValueTask StartAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();
        _job = WindowsKillOnCloseJob.Create();
        try
        {
            if (!_process.Start())
            {
                throw new InvalidOperationException("Elevated PowerShell could not be started.");
            }

            _started = true;
            WindowsKillOnCloseJob.Assign(_job, _process.Handle);
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.CompletedTask;
        }
        catch
        {
            TerminateSynchronously();
            throw;
        }
    }

    public async ValueTask WriteStandardInputAsync(
        ReadOnlyMemory<char> text,
        CancellationToken cancellationToken)
    {
        EnsureStarted();
        await _process.StandardInput.WriteAsync(text, cancellationToken).ConfigureAwait(false);
        await _process.StandardInput.FlushAsync(cancellationToken).ConfigureAwait(false);
        await _process.StandardInput.DisposeAsync().ConfigureAwait(false);
    }

    public Task WaitForExitAsync(CancellationToken cancellationToken)
    {
        EnsureStarted();
        return _process.WaitForExitAsync(cancellationToken);
    }

    public async ValueTask TerminateAsync()
    {
        if (!_started || HasExited)
        {
            DisposeJob();
            return;
        }

        // Closing a KILL_ON_JOB_CLOSE handle terminates PowerShell and every child
        // assigned to the job, including descendants created after launch.
        DisposeJob();
        if (await WaitForExitAsync(TerminationTimeout).ConfigureAwait(false))
        {
            return;
        }

        try
        {
            _process.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException)
        {
            return;
        }

        if (!await WaitForExitAsync(TerminationTimeout).ConfigureAwait(false))
        {
            throw new InvalidOperationException("The elevated PowerShell process tree did not terminate.");
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        try
        {
            if (_started && !HasExited)
            {
                await TerminateAsync().ConfigureAwait(false);
            }
        }
        finally
        {
            DisposeJob();
            _process.Dispose();
        }
    }

    private async Task<bool> WaitForExitAsync(TimeSpan timeout)
    {
        if (HasExited)
        {
            return true;
        }

        using var cancellation = new CancellationTokenSource(timeout);
        try
        {
            await _process.WaitForExitAsync(cancellation.Token).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            return HasExited;
        }
    }

    private void TerminateSynchronously()
    {
        DisposeJob();
        if (!_started || HasExited)
        {
            return;
        }

        try
        {
            _process.Kill(entireProcessTree: true);
            _process.WaitForExit(checked((int)TerminationTimeout.TotalMilliseconds));
        }
        catch (InvalidOperationException)
        {
        }
    }

    private void DisposeJob()
    {
        Interlocked.Exchange(ref _job, null)?.Dispose();
    }

    private void EnsureStarted()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_started)
        {
            throw new InvalidOperationException("The contained process has not started.");
        }
    }
}

internal static class WindowsKillOnCloseJob
{
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const int JobObjectExtendedLimitInformationClass = 9;

    public static SafeFileHandle Create()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows Job Objects are available only on Windows.");
        }

        var job = CreateJobObject(IntPtr.Zero, null);
        if (job.IsInvalid)
        {
            job.Dispose();
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        var information = new JobObjectExtendedLimitInformation
        {
            BasicLimitInformation = new JobObjectBasicLimitInformation
            {
                LimitFlags = JobObjectLimitKillOnJobClose,
            },
        };
        if (!SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformationClass,
                ref information,
                (uint)Marshal.SizeOf<JobObjectExtendedLimitInformation>()))
        {
            var error = new Win32Exception(Marshal.GetLastWin32Error());
            job.Dispose();
            throw error;
        }

        return job;
    }

    public static void Assign(SafeFileHandle job, IntPtr processHandle)
    {
        ArgumentNullException.ThrowIfNull(job);
        if (job.IsInvalid || job.IsClosed || !AssignProcessToJobObject(job, processHandle))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                "The elevated process could not be assigned to its kill-on-close Job Object.");
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateJobObjectW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateJobObject(IntPtr jobAttributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(
        SafeFileHandle job,
        int informationClass,
        ref JobObjectExtendedLimitInformation information,
        uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(SafeFileHandle job, IntPtr process);
}
