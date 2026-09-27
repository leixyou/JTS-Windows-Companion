using System.Buffers.Binary;
using System.Security.Cryptography;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.WorkerIpc;

internal enum WorkerMessage : byte { Execute = 1, Pulse = 2, Output = 16, Result = 17 }
internal enum WorkerOutcome : byte { Succeeded, Failed, Cancelled, Unknown, PowerShellNonzero }
internal sealed class WorkerIpcException() : IOException("WORKER_IPC_REJECTED");

/// <summary>One reader and one serialized writer per authenticated, single-task local pipe.</summary>
internal sealed class WorkerWire(Stream stream, Guid session)
{
    internal const int HeaderBytes = 48;
    internal const int MaximumBody = 65_629;
    private uint _sent, _received;
    internal async Task SendAsync(WorkerMessage type, Guid job, ReadOnlyMemory<byte> body, CancellationToken token)
    {
        if (session == Guid.Empty || job == Guid.Empty || _sent == uint.MaxValue || !ValidSize(type, body.Length)) throw new WorkerIpcException();
        var header = new byte[HeaderBytes]; "JTW1"u8.CopyTo(header);
        header[4] = (byte)type;
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8), (uint)body.Length);
        session.TryWriteBytes(header.AsSpan(12, 16), true, out _);
        job.TryWriteBytes(header.AsSpan(28, 16), true, out _);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(44), ++_sent);
        await stream.WriteAsync(header, token).ConfigureAwait(false);
        await stream.WriteAsync(body, token).ConfigureAwait(false);
        await stream.FlushAsync(token).ConfigureAwait(false);
    }
    internal async Task<WorkerFrame> ReadAsync(CancellationToken token)
    {
        var header = new byte[HeaderBytes];
        await stream.ReadExactlyAsync(header, token).ConfigureAwait(false);
        var kind = (WorkerMessage)header[4];
        var length = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(8));
        var sequence = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(44));
        var job = new Guid(header.AsSpan(28, 16), true);
        if (!header.AsSpan(0, 4).SequenceEqual("JTW1"u8) || header[5] != 0 || header[6] != 0 || header[7] != 0
            || new Guid(header.AsSpan(12, 16), true) != session || session == Guid.Empty || job == Guid.Empty
            || _received == uint.MaxValue || sequence != _received + 1 || length > MaximumBody || !ValidSize(kind, (int)length))
            throw new WorkerIpcException();
        var body = new byte[(int)length];
        try
        {
            await stream.ReadExactlyAsync(body, token).ConfigureAwait(false);
            _received = sequence; return new WorkerFrame(kind, job, body);
        }
        catch { CryptographicOperations.ZeroMemory(body); throw; }
    }
    private static bool ValidSize(WorkerMessage type, int length) => type switch
    {
        WorkerMessage.Execute => length is >= 94 and <= MaximumBody,
        WorkerMessage.Pulse => length == 0,
        WorkerMessage.Output => length is >= 1 and <= 4096,
        WorkerMessage.Result => length == 1,
        _ => false,
    };
}

internal sealed class WorkerFrame(WorkerMessage type, Guid job, byte[] body) : IDisposable
{
    internal WorkerMessage Type { get; } = type;
    internal Guid Job { get; } = job;
    internal byte[] Body { get; } = body;
    public void Dispose() => CryptographicOperations.ZeroMemory(Body);
}

internal static class WorkerRequestCodec
{
    internal static byte[] Encode(JobBinding binding, ReadOnlyMemory<byte> payload, DateTimeOffset now)
    {
        Validate(binding, payload.Span, now);
        var result = new byte[93 + payload.Length];
        BinaryPrimitives.WriteInt64BigEndian(result, binding.Deadline.ToUnixTimeMilliseconds());
        result[8] = binding.AllowDisconnected ? (byte)1 : (byte)0;
        binding.GrantId.TryWriteBytes(result.AsSpan(9, 16), true, out _);
        Convert.FromHexString(binding.OwnerDeviceId).CopyTo(result, 25);
        Convert.FromHexString(binding.PayloadSha256).CopyTo(result, 57);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(89), (uint)payload.Length);
        payload.Span.CopyTo(result.AsSpan(93)); return result;
    }
    internal static (JobBinding Binding, ReadOnlyMemory<byte> Payload) Decode(WorkerFrame frame, DateTimeOffset now)
    {
        if (frame.Type != WorkerMessage.Execute || frame.Body.Length < 94) throw new WorkerIpcException();
        var body = frame.Body;
        if (body[8] > 1 || BinaryPrimitives.ReadUInt32BigEndian(body.AsSpan(89)) != body.Length - 93) throw new WorkerIpcException();
        try
        {
            var binding = new JobBinding(frame.Job, "powershell.v1", Convert.ToHexString(body.AsSpan(25, 32)).ToLowerInvariant(),
                new Guid(body.AsSpan(9, 16), true), DateTimeOffset.FromUnixTimeMilliseconds(BinaryPrimitives.ReadInt64BigEndian(body)),
                body[8] == 1, Convert.ToHexString(body.AsSpan(57, 32)).ToLowerInvariant());
            var payload = body.AsMemory(93); Validate(binding, payload.Span, now); return (binding, payload);
        }
        catch (ArgumentException) { throw new WorkerIpcException(); }
    }
    private static void Validate(JobBinding binding, ReadOnlySpan<byte> payload, DateTimeOffset now)
    {
        if (binding.Kind != "powershell.v1" || binding.RequestId == Guid.Empty || binding.GrantId == Guid.Empty
            || !Hash(binding.OwnerDeviceId) || !Hash(binding.PayloadSha256) || payload.Length is 0 or > 65_536
            || JobBinding.Hash(payload) != binding.PayloadSha256 || binding.Deadline <= now || binding.Deadline > now.AddHours(24)
            || binding.Deadline.Ticks % TimeSpan.TicksPerMillisecond != 0) throw new WorkerIpcException();
    }
    private static bool Hash(string value) => value is { Length: 64 } && value.All(c => c is >= 'a' and <= 'f' or >= '0' and <= '9');
}
