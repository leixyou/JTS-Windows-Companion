using JTS.WindowsCompanion.Execution;
using JTS.WindowsCompanion.Pairing;
using Xunit;

namespace JTS.WindowsCompanion.AuthorityService.Tests;

public sealed class ResourceOwnershipTests
{
    [Fact]
    public async Task FailedDrainRetainsResourcesAndExplicitRetryDisposesInReverseOrder()
    {
        var order = new List<string>(); var attempts = 0;
        var runtime = new AuthorityRuntime(DateTimeOffset.UtcNow.AddDays(1), _ => Task.CompletedTask,
            () => ++attempts == 1 ? ValueTask.FromException(new IOException()) : ValueTask.CompletedTask,
            [new Resource("identity", order), new Resource("store", order), new Resource("client", order)]);
        await Assert.ThrowsAsync<IOException>(() => runtime.DisposeAsync().AsTask()); Assert.Empty(order);
        await runtime.DisposeAsync(); await runtime.DisposeAsync();
        Assert.Equal(new[] { "client", "store", "identity" }, order);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => runtime.RunAsync(CancellationToken.None));
    }
    [Fact]
    public async Task OneResourceFailureDoesNotLeakRemainingLeases()
    {
        var order = new List<string>();
        var runtime = new AuthorityRuntime(DateTimeOffset.UtcNow.AddDays(1), _ => Task.CompletedTask, () => ValueTask.CompletedTask,
            [new Resource("identity", order), new Resource("store", order, true), new Resource("client", order)]);
        await Assert.ThrowsAsync<AuthorityException>(() => runtime.DisposeAsync().AsTask());
        Assert.Equal(new[] { "client", "store", "identity" }, order); await runtime.DisposeAsync();
        Assert.Equal(3, order.Count);
    }
    [Fact]
    public async Task SimultaneousDisposalRunsDrainAndReleaseOnlyOnce()
    {
        var count = 0; var order = new List<string>();
        var runtime = new AuthorityRuntime(DateTimeOffset.UtcNow.AddDays(1), _ => Task.CompletedTask,
            async () => { count++; await Task.Yield(); }, [new Resource("identity", order)]);
        await Task.WhenAll(runtime.DisposeAsync().AsTask(), runtime.DisposeAsync().AsTask());
        Assert.Equal(1, count); Assert.Single(order);
    }
    [NonWindowsFact]
    public void NativeBoundariesRefuseThisHostRatherThanWeakeningPolicy()
    {
        Assert.Throws<PlatformNotSupportedException>(() => WindowsStandardAccount.VerifyCurrent("S-1-5-21-111-222-333-1001"));
        Assert.Throws<PlatformNotSupportedException>(() => WindowsProtectedDataPath.Require("unused", "S-1-5-21-111-222-333-1001"));
    }
    private sealed class Resource(string name, List<string> order, bool fail = false) : IDisposable
    { public void Dispose() { order.Add(name); if (fail) throw new IOException(); } }
}
internal sealed class NonWindowsFactAttribute : FactAttribute
{ public NonWindowsFactAttribute() { if (OperatingSystem.IsWindows()) Skip = "Non-Windows refusal case only."; } }
