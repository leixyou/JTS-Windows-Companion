using System.Net.WebSockets;

namespace JTS.WindowsCompanion.Relay;

/// <summary>Ordered, bounded binary carrier. TLS, not this carrier, authenticates and encrypts endpoint data.</summary>
public sealed class RelayWebSocketStream : Stream
{
    public const int MaximumWriteChunkBytes = 16 * 1024;
    private readonly WebSocket _socket;
    private readonly SemaphoreSlim _reader = new(1, 1);
    private readonly SemaphoreSlim _writer = new(1, 1);
    private bool _disposed;
    internal RelayWebSocketStream(WebSocket socket) => _socket = socket;

    internal static async Task ExpectReadyAsync(WebSocket socket, RelayBinding binding, CancellationToken token)
    {
        var buffer = new byte[1024];
        var length = 0;
        var emptyFragments = 0;
        while (true)
        {
            if (length == buffer.Length) throw new RelayProtocolException("RELAY_READY_LIMIT");
            var result = await socket.ReceiveAsync(buffer.AsMemory(length), token).ConfigureAwait(false);
            if (result.MessageType != WebSocketMessageType.Text) throw new RelayProtocolException("RELAY_READY_REQUIRED");
            emptyFragments = result.Count == 0 ? emptyFragments + 1 : 0;
            if (emptyFragments > 8) throw new RelayProtocolException("RELAY_EMPTY_FRAGMENT_LIMIT");
            length += result.Count;
            if (result.EndOfMessage) break;
        }
        using var json = RelayWire.Parse(buffer.AsMemory(0, length));
        RelayWire.Properties(json.RootElement, "ready", "sessionId", "lane");
        if (json.RootElement.GetProperty("ready").ValueKind != System.Text.Json.JsonValueKind.True
            || RelayWire.String(json.RootElement, "sessionId", 36) != binding.SessionId.ToString("D")
            || RelayWire.String(json.RootElement, "lane", 8) != RelayWire.LaneName(binding.Lane))
            throw new RelayProtocolException("RELAY_READY_MISMATCH");
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (buffer.IsEmpty) return 0;
        await _reader.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var emptyFragments = 0;
            while (true)
            {
                var result = await _socket.ReceiveAsync(buffer[..Math.Min(buffer.Length, 64 * 1024)], cancellationToken).ConfigureAwait(false);
                if (result.MessageType == WebSocketMessageType.Close) return 0;
                if (result.MessageType != WebSocketMessageType.Binary)
                    throw new RelayProtocolException("RELAY_BINARY_REQUIRED");
                // Empty fragments carry no bytes, and must not appear as stream EOF.
                if (result.Count != 0) return result.Count;
                if (++emptyFragments > 8) throw new RelayProtocolException("RELAY_EMPTY_FRAGMENT_LIMIT");
                cancellationToken.ThrowIfCancellationRequested();
            }
        }
        catch { _socket.Abort(); throw; }
        finally { _reader.Release(); }
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await _writer.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            while (!buffer.IsEmpty)
            {
                var count = Math.Min(buffer.Length, MaximumWriteChunkBytes);
                await _socket.SendAsync(buffer[..count], WebSocketMessageType.Binary, true, cancellationToken).ConfigureAwait(false);
                buffer = buffer[count..];
            }
        }
        catch { _socket.Abort(); throw; }
        finally { _writer.Release(); }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed) { _disposed = true; _socket.Abort(); _socket.Dispose(); }
        base.Dispose(disposing);
    }
    public override bool CanRead => !_disposed;
    public override bool CanWrite => !_disposed;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() { ObjectDisposedException.ThrowIf(_disposed, this); }
    public override Task FlushAsync(CancellationToken cancellationToken) { cancellationToken.ThrowIfCancellationRequested(); Flush(); return Task.CompletedTask; }
    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
