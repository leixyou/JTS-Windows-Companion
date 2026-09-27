using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace JTS.WindowsCompanion.Execution;

[SupportedOSPlatform("windows")]
internal sealed class WindowsStartupAttributes : IDisposable
{
    internal IntPtr Pointer { get; private set; }
    private readonly List<IntPtr> _values = [];
    private bool _initialized;
    internal WindowsStartupAttributes(IntPtr job, params IntPtr[] inheritedHandles)
    {
        nuint size = 0;
        WindowsNative.InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref size);
        if (size is 0 or > 1_048_576) throw new InvalidOperationException("WORKER_ATTRIBUTES_INVALID");
        Pointer = Marshal.AllocHGlobal(checked((nint)size));
        try
        {
            WindowsNative.Require(WindowsNative.InitializeProcThreadAttributeList(Pointer, 2, 0, ref size));
            _initialized = true;
            Add(0x00020002, inheritedHandles); // PROC_THREAD_ATTRIBUTE_HANDLE_LIST
            Add(0x0002000D, [job]); // PROC_THREAD_ATTRIBUTE_JOB_LIST: job assignment occurs inside CreateProcess.
        }
        catch { Dispose(); throw; }
    }
    private void Add(nuint attribute, IntPtr[] handles)
    {
        var value = Marshal.AllocHGlobal(IntPtr.Size * handles.Length); _values.Add(value);
        Marshal.Copy(handles, 0, value, handles.Length);
        WindowsNative.Require(WindowsNative.UpdateProcThreadAttribute(Pointer, 0, attribute, value,
            (nuint)(IntPtr.Size * handles.Length), IntPtr.Zero, IntPtr.Zero));
    }
    public void Dispose()
    {
        if (_initialized) { WindowsNative.DeleteProcThreadAttributeList(Pointer); _initialized = false; }
        foreach (var value in _values) Marshal.FreeHGlobal(value);
        _values.Clear();
        if (Pointer != IntPtr.Zero) { Marshal.FreeHGlobal(Pointer); Pointer = IntPtr.Zero; }
    }
}
