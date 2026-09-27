using System.Buffers.Binary;
using JTS.WindowsCompanion.Runtime;
using Xunit;

namespace JTS.WindowsCompanion.WorkerIpc.Tests;

public sealed class WorkerWireTests
{
    internal static JobSubmission Job(byte[]? payload = null) => new(Guid.NewGuid(), "powershell.v1", new string('a', 64),
        Guid.NewGuid(), DateTimeOffset.UtcNow.AddMinutes(1), payload ?? "payload"u8.ToArray(), true);
    [Fact]
    public async Task MaximumPayloadRoundTripsExactBindingAndSensitiveBuffersAreCleared()
    {
        var job = Job(new byte[65_536]); var body = WorkerRequestCodec.Encode(job.Binding, job.Payload, DateTimeOffset.UtcNow);
        using var stream = new MemoryStream(); var session = Guid.NewGuid();
        await new WorkerWire(stream, session).SendAsync(WorkerMessage.Execute, job.Binding.RequestId, body, default);
        stream.Position = 0;
        var frame = await new WorkerWire(stream, session).ReadAsync(default);
        var request = WorkerRequestCodec.Decode(frame, DateTimeOffset.UtcNow);
        Assert.Equal(job.Binding, request.Binding); Assert.Equal(job.Payload.ToArray(), request.Payload.ToArray());
        frame.Dispose(); Assert.All(frame.Body, b => Assert.Equal(0, b));
    }
    [Theory]
    [InlineData(0)] // magic
    [InlineData(4)] // unsupported type
    [InlineData(5)] // reserved
    [InlineData(12)] // different session
    [InlineData(44)] // sequence
    public async Task CorruptHeaderIsRejectedBeforeBody(int offset)
    {
        using var encoded = new MemoryStream(); var session = Guid.NewGuid();
        await new WorkerWire(encoded, session).SendAsync(WorkerMessage.Output, Guid.NewGuid(), "out"u8.ToArray(), default);
        var bytes = encoded.ToArray(); bytes[offset] ^= 0x80;
        using var source = new MemoryStream(bytes[..WorkerWire.HeaderBytes]);
        await Assert.ThrowsAsync<WorkerIpcException>(() => new WorkerWire(source, session).ReadAsync(default));
        Assert.Equal(WorkerWire.HeaderBytes, source.Position);
    }
    [Fact]
    public async Task OversizedLengthAndEmptyJobFailWithoutAllocatingBody()
    {
        using var encoded = new MemoryStream(); var session = Guid.NewGuid();
        await new WorkerWire(encoded, session).SendAsync(WorkerMessage.Output, Guid.NewGuid(), "out"u8.ToArray(), default);
        var bytes = encoded.ToArray(); BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(8), uint.MaxValue);
        await Assert.ThrowsAsync<WorkerIpcException>(() => new WorkerWire(new MemoryStream(bytes[..48]), session).ReadAsync(default));
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(8), 3); bytes.AsSpan(28, 16).Clear();
        await Assert.ThrowsAsync<WorkerIpcException>(() => new WorkerWire(new MemoryStream(bytes[..48]), session).ReadAsync(default));
    }
    [Fact]
    public async Task RepeatedFrameSequenceCannotReplay()
    {
        using var encoded = new MemoryStream(); var session = Guid.NewGuid();
        await new WorkerWire(encoded, session).SendAsync(WorkerMessage.Pulse, Guid.NewGuid(), Array.Empty<byte>(), default);
        var bytes = encoded.ToArray(); encoded.Write(bytes); encoded.Position = 0;
        var wire = new WorkerWire(encoded, session); using var first = await wire.ReadAsync(default);
        await Assert.ThrowsAsync<WorkerIpcException>(() => wire.ReadAsync(default));
    }
    [Theory]
    [InlineData(8)] // detached flag
    [InlineData(25)] // owner is valid but different, accepted; tested separately via binding round trip
    [InlineData(57)] // payload hash
    [InlineData(89)] // payload count
    public void PayloadTamperingDoesNotRelaxValidation(int offset)
    {
        var job = Job(); var body = WorkerRequestCodec.Encode(job.Binding, job.Payload, DateTimeOffset.UtcNow);
        body[offset] ^= 0x80;
        using var frame = new WorkerFrame(WorkerMessage.Execute, job.Binding.RequestId, body);
        if (offset == 25) Assert.NotEqual(job.Binding.OwnerDeviceId, WorkerRequestCodec.Decode(frame, DateTimeOffset.UtcNow).Binding.OwnerDeviceId);
        else Assert.Throws<WorkerIpcException>(() => WorkerRequestCodec.Decode(frame, DateTimeOffset.UtcNow));
    }
    [Fact]
    public void WrongKindExpiredDeadlineAndPayloadHashAreRejected()
    {
        var job = Job();
        foreach (var bad in new[] { job.Binding with { Kind = "system.shell" }, job.Binding with { Deadline = DateTimeOffset.UtcNow.AddMinutes(-1) },
            job.Binding with { PayloadSha256 = new string('0', 64) }, job.Binding with { GrantId = Guid.Empty } })
            Assert.Throws<WorkerIpcException>(() => WorkerRequestCodec.Encode(bad, job.Payload, DateTimeOffset.UtcNow));
    }
}
