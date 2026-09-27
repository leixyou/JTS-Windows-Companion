using System.IO.Pipes;
using System.Runtime.Versioning;

namespace JTS.WindowsCompanion.Execution;

[SupportedOSPlatform("windows")]
internal sealed class WindowsWorkerPipe : IDisposable
{
    internal NamedPipeServerStream Parent { get; }
    internal NamedPipeClientStream Child { get; }
    internal WindowsWorkerPipe(PipeDirection parentDirection)
    {
        var name = "jts-worker-" + Guid.NewGuid().ToString("N");
        Parent = new NamedPipeServerStream(name, parentDirection, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly, 4096, 4096);
        Child = new NamedPipeClientStream(".", name,
            parentDirection == PipeDirection.In ? PipeDirection.Out : PipeDirection.In, PipeOptions.None);
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            var accept = Parent.WaitForConnectionAsync(timeout.Token);
            Child.Connect(3000);
            accept.GetAwaiter().GetResult();
            WindowsNative.Require(WindowsNative.SetHandleInformation(Child.SafePipeHandle, 1, 1));
        }
        catch { Dispose(); throw; }
    }
    public void Dispose() { Child.Dispose(); Parent.Dispose(); }
}
