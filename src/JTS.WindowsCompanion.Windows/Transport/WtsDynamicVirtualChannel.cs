using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Security;
using JTS.WindowsCompanion.Transport;
using Microsoft.Win32.SafeHandles;

namespace JTS.WindowsCompanion.Windows.Transport;

public sealed class WtsDynamicVirtualChannel : ICompanionChannel
{
    private const uint CurrentSession = 0xFFFFFFFF;
    private const uint DynamicChannel = 0x00000001;
    private const int NativeReadBufferBytes = 16 * 1024;
    private readonly string _channelName;
    private readonly CompanionFrameDecoder _decoder = new();
    private readonly DvcPduReassembler _pduReassembler = new();
    private readonly SemaphoreSlim _sendGate = new(1, 1);
    private readonly WtsNativeCallGate _nativeCalls = new();
    private readonly ISecurityEventSink _events;
    private int _diagnosticWrites;
    private SafeWtsVirtualChannelHandle? _handle;
    private bool _disposed;

    public WtsDynamicVirtualChannel(string? channelName = null, ISecurityEventSink? events = null)
    {
        _events = events ?? NullSecurityEventSink.Instance;
        _channelName = string.IsNullOrWhiteSpace(channelName)
            ? CompanionProtocol.DynamicVirtualChannelName
            : channelName;
        if (_channelName.Length is < 1 or > 255
            || _channelName.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_')))
        {
            throw new ArgumentException("The Dynamic Virtual Channel name is invalid.", nameof(channelName));
        }
    }

    public bool IsConnected => _handle is { IsInvalid: false, IsClosed: false };

    public ValueTask ConnectAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureWindows();
        if (IsConnected)
        {
            return ValueTask.CompletedTask;
        }

        ResetReceiveState();
        var handle = NativeMethods.WTSVirtualChannelOpenEx(CurrentSession, _channelName, DynamicChannel);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw new CompanionChannelUnavailableException("open", error,
                new Win32Exception(error, "The RDP Dynamic Virtual Channel could not be opened."));
        }

        _handle = handle;
        return ValueTask.CompletedTask;
    }

    public async ValueTask<CompanionFrame> ReceiveAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        try
        {
            var handle = GetConnectedHandle();
            while (true)
            {
                if (_decoder.TryRead(out var frame))
                {
                    return frame!;
                }

                var pdu = await Task.Run(() => ReadNativeAsync(handle, cancellationToken), cancellationToken).ConfigureAwait(false);
                if (_pduReassembler.TryAppend(pdu, out var message))
                {
                    _decoder.Append(message.Span);
                }
            }
        }
        catch (Win32Exception exception)
        {
            ResetReceiveState();
            throw new CompanionChannelUnavailableException("read", exception.NativeErrorCode, exception);
        }
        catch
        {
            ResetReceiveState();
            throw;
        }
    }

    public async ValueTask SendAsync(CompanionFrame frame, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var handle = GetConnectedHandle();
        var encoded = CompanionFrameCodec.Encode(frame);
        await _sendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var offset = 0;
            while (offset < encoded.Length)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var count = Math.Min(NativeReadBufferBytes, encoded.Length - offset);
                var writeBuffer = encoded.AsSpan(offset, count).ToArray();
                var trace = Interlocked.Increment(ref _diagnosticWrites) <= 16;
                RecordWriteStage("native-write-wait", count, trace);
                var result = await _nativeCalls.InvokeAsync(() =>
                {
                    RecordWriteStage("native-write-begin", count, trace);
                    var succeeded = NativeMethods.WTSVirtualChannelWrite(handle, writeBuffer, writeBuffer.Length, out var bytesWritten);
                    var error = succeeded ? 0 : Marshal.GetLastPInvokeError();
                    RecordWriteStage(succeeded ? "native-write-complete" : "native-write-failed", succeeded ? bytesWritten : error, trace);
                    return (Succeeded: succeeded, BytesWritten: bytesWritten, Error: error);
                }, cancellationToken).ConfigureAwait(false);
                if (!result.Succeeded)
                {
                    throw new CompanionChannelUnavailableException("write", result.Error,
                        new Win32Exception(result.Error, "Writing to the RDP Dynamic Virtual Channel failed."));
                }

                var written = result.BytesWritten;
                if (written <= 0 || written > writeBuffer.Length)
                {
                    throw new IOException("The RDP Dynamic Virtual Channel returned an invalid write count.");
                }

                offset += written;
            }
        }
        finally
        {
            _sendGate.Release();
        }
    }

    public ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return ValueTask.CompletedTask;
        }

        ResetReceiveState();
        _handle?.Dispose();
        _sendGate.Dispose();
        _nativeCalls.Dispose();
        _disposed = true;
        return ValueTask.CompletedTask;
    }

    private Task<byte[]> ReadNativeAsync(SafeWtsVirtualChannelHandle handle, CancellationToken cancellationToken) =>
        WtsChannelReadLoop.ReadAsync(buffer =>
            _nativeCalls.Invoke(() =>
            {
                var succeeded = NativeMethods.WTSVirtualChannelRead(handle, 500, buffer, buffer.Length, out var bytesRead);
                var error = succeeded ? 0 : Marshal.GetLastPInvokeError();
                return new WtsChannelReadResult(succeeded, bytesRead, error);
            }, cancellationToken), NativeReadBufferBytes, cancellationToken);

    private void RecordWriteStage(string stage, int countOrError, bool enabled)
    {
        if (enabled) _events.Record(new SecurityEvent(DateTimeOffset.UtcNow, "transport", stage,
            "progress", countOrError.ToString(CultureInfo.InvariantCulture)));
    }

    private SafeWtsVirtualChannelHandle GetConnectedHandle() => IsConnected
        ? _handle!
        : throw new InvalidOperationException("The RDP Dynamic Virtual Channel is not connected.");

    private void ResetReceiveState()
    {
        _pduReassembler.Reset();
        _decoder.Reset();
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("WTS Dynamic Virtual Channels are available only on Windows.");
        }
    }

    private sealed class SafeWtsVirtualChannelHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeWtsVirtualChannelHandle()
            : base(ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle() => NativeMethods.WTSVirtualChannelClose(handle);
    }

    private static class NativeMethods
    {
        [DllImport("wtsapi32.dll", EntryPoint = "WTSVirtualChannelOpenEx", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        internal static extern SafeWtsVirtualChannelHandle WTSVirtualChannelOpenEx(
            uint sessionId,
            string virtualName,
            uint flags);

        [DllImport("wtsapi32.dll", EntryPoint = "WTSVirtualChannelRead", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool WTSVirtualChannelRead(
            SafeWtsVirtualChannelHandle channel,
            uint timeoutMilliseconds,
            [Out] byte[] buffer,
            int bufferSize,
            out int bytesRead);

        [DllImport("wtsapi32.dll", EntryPoint = "WTSVirtualChannelWrite", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool WTSVirtualChannelWrite(
            SafeWtsVirtualChannelHandle channel,
            byte[] buffer,
            int length,
            out int bytesWritten);

        [DllImport("wtsapi32.dll", EntryPoint = "WTSVirtualChannelClose", ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool WTSVirtualChannelClose(nint channel);
    }
}
