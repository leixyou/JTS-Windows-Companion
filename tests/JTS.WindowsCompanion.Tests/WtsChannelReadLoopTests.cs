using System.Buffers.Binary;
using System.ComponentModel;
using System.IO;
using JTS.WindowsCompanion.Windows.Transport;

namespace JTS.WindowsCompanion.Tests;

public sealed class WtsChannelReadLoopTests
{
    [Fact]
    public async Task IncompleteReadWaitsBeforeReturningCompletedData()
    {
        var calls = 0;
        var delayStarted = new TaskCompletionSource<TimeSpan>(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseDelay = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var pending = WtsChannelReadLoop.ReadAsync(buffer =>
        {
            calls++;
            if (calls == 1) return new(false, 0, 996);
            "ready"u8.CopyTo(buffer);
            return new(true, 5, 0);
        }, 32, CancellationToken.None, (delay, _) =>
        {
            delayStarted.SetResult(delay);
            return releaseDelay.Task;
        });

        var requestedDelay = await delayStarted.Task;
        Assert.InRange(requestedDelay.TotalMilliseconds, 20, 500);
        Assert.Equal(1, calls);
        Assert.False(pending.IsCompleted);
        releaseDelay.SetResult();
        Assert.Equal("ready"u8.ToArray(), await pending);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task EmptyAndTimeoutResultsArePacedWithoutResettingPartialPdu()
    {
        var reassembler = new DvcPduReassembler();
        Assert.False(reassembler.TryAppend(Pdu(4, DvcPduFlags.First, [1, 2]), out _));
        var idle = new Queue<WtsChannelReadResult>([
            new(false, 0, 996), new(false, 0, 121), new(false, 0, 1460),
            new(false, 0, 0), new(true, 0, 0),
        ]);
        var waits = 0;
        var pdu = Pdu(4, DvcPduFlags.Last, [3, 4]);
        var received = await WtsChannelReadLoop.ReadAsync(buffer =>
        {
            if (idle.TryDequeue(out var result)) return result;
            pdu.CopyTo(buffer, 0);
            return new(true, pdu.Length, 0);
        }, 32, CancellationToken.None, (_, _) => { waits++; return Task.CompletedTask; });

        Assert.Equal(5, waits);
        Assert.True(reassembler.TryAppend(received, out var message));
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, message.ToArray());
    }

    [Fact]
    public async Task CancellationStopsIdleReadWithoutAnotherNativeAttempt()
    {
        using var cancellation = new CancellationTokenSource();
        var calls = 0;
        var waiting = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var pending = WtsChannelReadLoop.ReadAsync(_ =>
        {
            calls++;
            return new(false, 0, 996);
        }, 32, cancellation.Token, (_, token) =>
        {
            waiting.SetResult();
            return Task.Delay(Timeout.InfiniteTimeSpan, token);
        });
        await waiting.Task;
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
        Assert.Equal(1, calls);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => WtsChannelReadLoop.ReadAsync(_ =>
        {
            calls++;
            return new(true, 1, 0);
        }, 32, cancellation.Token));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task HardFailuresAndFailedPartialReadsRetainNativeErrorWithoutRetry()
    {
        foreach (var result in new WtsChannelReadResult[] {
            new(false, 0, 5), new(false, 0, 6), new(false, 0, 109),
            new(false, 0, 233), new(false, 0, 995), new(false, 1, 996),
        })
        {
            var calls = 0;
            var failure = await Assert.ThrowsAsync<Win32Exception>(() => WtsChannelReadLoop.ReadAsync(_ =>
            {
                calls++;
                return result;
            }, 32, CancellationToken.None, (_, _) => throw new InvalidOperationException("Must not retry a hard failure.")));
            Assert.Equal(result.ErrorCode, failure.NativeErrorCode);
            Assert.Equal(1, calls);
        }
    }

    [Fact]
    public async Task InvalidNativeCountsAreRejectedBeforeCopying()
    {
        foreach (var count in new[] { -1, 33 })
        {
            await Assert.ThrowsAsync<InvalidDataException>(() => WtsChannelReadLoop.ReadAsync(
                _ => new(true, count, 0), 32, CancellationToken.None));
        }
    }

    private static byte[] Pdu(int length, DvcPduFlags flags, byte[] payload)
    {
        var bytes = new byte[DvcPduReassembler.HeaderLength + payload.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, (uint)length);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), (uint)flags);
        payload.CopyTo(bytes, DvcPduReassembler.HeaderLength);
        return bytes;
    }
}
