using JTS.WindowsCompanion.Runtime;
using Xunit;

namespace JTS.WindowsCompanion.Control.Tests;

public sealed class RevocationDrainTests
{
    [Fact]
    public async Task DurableGrantAndPeerRevocationDrainsPinnedStreamAndDetachedWork()
    {
        await using var f = new ControlFixture(durableGrants: true);
        await using var client = await f.ConnectAsync();
        var id = Guid.NewGuid(); using var response = await client.CallAsync("job.submit", f.Submission(id, "fixture.block", true));
        Assert.True(response.RootElement.GetProperty("ok").GetBoolean());
        await f.Started.Task.WaitAsync(TimeSpan.FromSeconds(3));
        await f.DurableGrants!.RevokeAsync(f.ClientIdentity.DeviceId, f.GrantId, CancellationToken.None);
        f.Host.RevokePeer(f.ClientIdentity.DeviceId); f.Host.RevokeGrant(f.ClientIdentity.DeviceId, f.GrantId);
        await f.Host.DrainRevokedPeerAsync(f.ClientIdentity.DeviceId);
        await client.WaitForServerCompletionAsync();
        Assert.Equal(DurableJobState.Cancelled, f.Store.Get(id, f.ClientIdentity.DeviceId, f.GrantId).State);
        Assert.NotNull(Assert.Single(f.DurableGrants!.ListLocally()).RevokedAt);
        Assert.Equal(1, f.Executions);
    }
}
