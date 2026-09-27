using JTS.WindowsCompanion.Agent;
using JTS.WindowsCompanion.Automation;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Windows.Automation;

namespace JTS.WindowsCompanion.Tests;

public sealed class UiAutomationBoundsTests
{
    [Theory]
    [InlineData(double.PositiveInfinity, double.PositiveInfinity, double.NegativeInfinity, double.NegativeInfinity)]
    [InlineData(double.NaN, 1, 2, 3)]
    [InlineData(1, double.NegativeInfinity, 2, 3)]
    [InlineData(1, 2, double.PositiveInfinity, 3)]
    [InlineData(1, 2, 3, double.NaN)]
    [InlineData(1, 2, -1, 3)]
    [InlineData(1, 2, 3, -1)]
    public void UnavailableProviderGeometryHasFiniteZeroAreaOnTheWire(
        double x, double y, double width, double height)
    {
        var bounds = UiAutomationBounds.FromProvider(x, y, width, height);

        Assert.Equal(new UiaBounds(0, 0, 0, 0), bounds);
        var wire = ControlMessageSerializer.ToElement(bounds);
        Assert.All(wire.EnumerateObject(), property => Assert.Equal(0, property.Value.GetDouble()));
    }

    [Theory]
    [InlineData(-1920, -1080, 800, 600)]
    [InlineData(0.5, 12.25, 0, 0)]
    [InlineData(12, 34, 56, 78)]
    public void FiniteProviderGeometryIsPreserved(
        double x, double y, double width, double height)
    {
        Assert.Equal(new UiaBounds(x, y, width, height),
            UiAutomationBounds.FromProvider(x, y, width, height));
    }

    [Fact]
    public async Task EmptyDeepNodeDoesNotTurnAValidSnapshotIntoRequestInvalid()
    {
        var rawEmptyBounds = new UiaBounds(
            double.PositiveInfinity, double.PositiveInfinity,
            double.NegativeInfinity, double.NegativeInfinity);
        var raw = SnapshotWithDepthFour(rawEmptyBounds);
        Assert.Throws<ArgumentException>(() => CompanionResponse.Ok(Guid.NewGuid(), raw));

        var currentSnapshot = raw;
        var router = new CompanionRequestRouter(new TestAuthorizationGate());
        router.Register("uia.snapshot", (_, _) => ValueTask.FromResult<object?>(currentSnapshot));
        var request = new CompanionRequest(
            CompanionProtocol.CurrentVersion,
            Guid.NewGuid(),
            "uia.snapshot",
            DateTimeOffset.UtcNow.AddSeconds(10).ToUnixTimeMilliseconds(),
            null,
            null,
            ControlMessageSerializer.ToElement(new { maximumDepth = 4, maximumNodes = 100 }));
        var rawResponse = await router.DispatchAsync(request,
            DateTimeOffset.UtcNow,
            CancellationToken.None);
        Assert.False(rawResponse.Success);
        Assert.Equal("REQUEST_INVALID", rawResponse.Error?.Code);

        currentSnapshot = SnapshotWithDepthFour(UiAutomationBounds.FromProvider(
            rawEmptyBounds.X, rawEmptyBounds.Y, rawEmptyBounds.Width, rawEmptyBounds.Height));
        var response = await router.DispatchAsync(request with { RequestId = Guid.NewGuid() },
            DateTimeOffset.UtcNow, CancellationToken.None);

        Assert.True(response.Success);
        Assert.Null(response.Error);
        Assert.Equal(5, response.Result!.Value.GetProperty("nodeCount").GetInt32());
        var node = response.Result.Value.GetProperty("root");
        for (var depth = 0; depth < 4; depth++)
        {
            node = node.GetProperty("children")[0];
        }
        Assert.Equal("hidden-leaf", node.GetProperty("runtimeId").GetString());
        Assert.True(node.GetProperty("isOffscreen").GetBoolean());
        Assert.Equal(0, node.GetProperty("bounds").GetProperty("width").GetDouble());
        Assert.Equal(0, node.GetProperty("bounds").GetProperty("height").GetDouble());
    }

    private static UiaSnapshot SnapshotWithDepthFour(UiaBounds leafBounds)
    {
        var node = new UiaElement(
            "hidden-leaf", null, null, "Pane", 123, true, true, leafBounds, []);
        for (var depth = 3; depth >= 0; depth--)
        {
            node = new UiaElement(
                $"parent-{depth}", null, null, "Pane", 123, true, false,
                new UiaBounds(0, 0, 100, 100), [node]);
        }
        return new UiaSnapshot(node, false, 5);
    }
}
