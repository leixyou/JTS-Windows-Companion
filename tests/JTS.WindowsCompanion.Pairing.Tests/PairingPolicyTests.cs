using Xunit;
using JTS.WindowsCompanion.Relay;

namespace JTS.WindowsCompanion.Pairing.Tests;

public sealed class PairingPolicyTests
{
    [Fact]
    public void PolicySnapshotsCallerCollectionsAndNeverInfersCapabilitiesFromLanes()
    {
        using var f = new PairingFixture(); var id = Guid.NewGuid(); var ids = new List<Guid> { id }; var lanes = new[] { RelayLane.Control };
        var policy = f.Policy(lanes: lanes, grants: new Dictionary<RelayLane, IReadOnlyList<Guid>> { [RelayLane.Control] = ids });
        ids.Clear(); lanes[0] = RelayLane.Rdp;
        Assert.Equal(id, Assert.Single(policy.GrantsFor(RelayLane.Control))); Assert.Equal(RelayLane.Control, Assert.Single(policy.AllowedLanes));
        Assert.Empty(f.Policy(lanes: Enum.GetValues<RelayLane>()).GrantsFor(RelayLane.Control));
    }

    [Theory]
    [InlineData("no_lanes")]
    [InlineData("duplicate_lane")]
    [InlineData("unknown_lane")]
    [InlineData("unknown_tls")]
    [InlineData("unpaired_grant")]
    [InlineData("cross_lane_grant")]
    [InlineData("empty_grant")]
    [InlineData("oversized")]
    public void InvalidOrAmbiguousLaneGrantsAreRejected(string kind)
    {
        using var f = new PairingFixture(); var id = Guid.NewGuid();
        Assert.Throws<ArgumentException>(() => kind switch
        {
            "no_lanes" => f.Policy(lanes: []),
            "duplicate_lane" => f.Policy(lanes: [RelayLane.Control, RelayLane.Control]),
            "unknown_lane" => f.Policy(lanes: [(RelayLane)99]),
            "unknown_tls" => f.Policy(tls: (RelayTlsPolicy)99),
            "unpaired_grant" => f.Policy(grants: new Dictionary<RelayLane, IReadOnlyList<Guid>> { [RelayLane.File] = [id] }),
            "cross_lane_grant" => f.Policy(lanes: [RelayLane.Control, RelayLane.File], grants: new Dictionary<RelayLane, IReadOnlyList<Guid>>
                { [RelayLane.Control] = [id], [RelayLane.File] = [id] }),
            "empty_grant" => f.Policy(grants: new Dictionary<RelayLane, IReadOnlyList<Guid>> { [RelayLane.Control] = [Guid.Empty] }),
            _ => f.Policy(grants: new Dictionary<RelayLane, IReadOnlyList<Guid>> { [RelayLane.Control] = Enumerable.Range(0, 4097).Select(_ => Guid.NewGuid()).ToArray() }),
        });
    }

    [Fact]
    public async Task MaximumBoundedGrantListRoundTripsWithoutTruncation()
    {
        using var f = new PairingFixture(); using var store = f.Create();
        var ids = Enumerable.Range(0, 4096).Select(_ => Guid.NewGuid()).ToArray();
        var policy = f.Policy(grants: new Dictionary<RelayLane, IReadOnlyList<Guid>> { [RelayLane.Control] = ids });
        store.ApproveLocally(policy, f.PeerId); var read = await store.FindAsync(f.PeerId);
        Assert.Equal(ids.Order(), read!.GrantsFor(RelayLane.Control));
    }
}
