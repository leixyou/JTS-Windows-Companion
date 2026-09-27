using System.ComponentModel;
using JTS.WindowsCompanion.Windows.Transport;

namespace JTS.WindowsCompanion.Tests;

public sealed class WtsNativeCallGateTests
{
    [Fact]
    public async Task PendingFiniteReadExcludesWriteUntilItReturns()
    {
        using var gate = new WtsNativeCallGate();
        using var releaseRead = new ManualResetEventSlim();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var readEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var nativeCallCount = 0;
        var read = Task.Run(() => gate.Invoke(() =>
        {
            Assert.Equal(1, Interlocked.Increment(ref nativeCallCount));
            readEntered.SetResult();
            try { releaseRead.Wait(timeout.Token); return 996; }
            finally { Interlocked.Decrement(ref nativeCallCount); }
        }, timeout.Token));
        await readEntered.Task.WaitAsync(timeout.Token);
        var write = gate.InvokeAsync(() =>
        {
            Assert.Equal(1, Interlocked.Increment(ref nativeCallCount));
            Interlocked.Decrement(ref nativeCallCount);
            return 512;
        }, timeout.Token).AsTask();
        try { Assert.False(write.IsCompleted); }
        finally { releaseRead.Set(); }
        Assert.Equal(996, await read);
        Assert.Equal(512, await write);
        Assert.Equal(0, nativeCallCount);
    }

    [Fact]
    public async Task CancelledWaiterNeverCallsNativeOrConsumesTheNextPermit()
    {
        using var gate = new WtsNativeCallGate();
        using var releaseRead = new ManualResetEventSlim();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var cancelled = new CancellationTokenSource();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var read = Task.Run(() => gate.Invoke(() =>
        {
            entered.SetResult();
            releaseRead.Wait(timeout.Token);
            return 0;
        }, timeout.Token));
        await entered.Task.WaitAsync(timeout.Token);
        var nativeWriteCalled = false;
        var waiting = gate.InvokeAsync(() => nativeWriteCalled = true, cancelled.Token).AsTask();
        cancelled.Cancel();
        try
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
            Assert.False(nativeWriteCalled);
        }
        finally { releaseRead.Set(); }
        await read;
        Assert.Equal(7, await gate.InvokeAsync(() => 7, timeout.Token));
        Assert.ThrowsAny<OperationCanceledException>(() => gate.Invoke(() => nativeWriteCalled = true, cancelled.Token));
        Assert.False(nativeWriteCalled);
    }

    [Fact]
    public async Task NativeFailureRemainsObservableAndReleasesGate()
    {
        using var gate = new WtsNativeCallGate();
        var failure = await Assert.ThrowsAsync<Win32Exception>(async () =>
            await gate.InvokeAsync<int>(() => throw new Win32Exception(109), CancellationToken.None));
        Assert.Equal(109, failure.NativeErrorCode);
        Assert.Equal(11, gate.Invoke(() => 11, CancellationToken.None));
        Assert.Throws<Win32Exception>(() => gate.Invoke<int>(() => throw new Win32Exception(6), CancellationToken.None));
        Assert.Equal(12, await gate.InvokeAsync(() => 12, CancellationToken.None));
    }
}
