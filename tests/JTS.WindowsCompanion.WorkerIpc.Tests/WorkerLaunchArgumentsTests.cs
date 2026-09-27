using Xunit;

namespace JTS.WindowsCompanion.WorkerIpc.Tests;

public sealed class WorkerLaunchArgumentsTests
{
    private static WorkerLaunchDescriptor Descriptor() => new(Guid.NewGuid(),
        new WindowsProcessIdentity(321, 1234567, "S-1-5-80-1-2-3-4-5", @"C:\Program Files\JTS\authority.exe", new string('a', 64)),
        "S-1-5-21-1-2-3-1001");
    [Fact]
    public void RoundTripContainsOnlyPublicRendezvousMetadata()
    {
        var original = Descriptor(); var args = WorkerLaunchArguments.Encode(original);
        Assert.Equal(7, args.Length); Assert.Equal(original, WorkerLaunchArguments.Decode(args));
    }
    [Theory]
    [InlineData(0, "00000000-0000-0000-0000-000000000000")]
    [InlineData(1, "0321")]
    [InlineData(1, "0")]
    [InlineData(2, "-1")]
    [InlineData(3, "S-1-5-18")]
    [InlineData(3, "S-1-5-80-1-2-3-4")]
    [InlineData(4, "relative.exe")]
    [InlineData(4, "C:\\x\" --other")]
    [InlineData(5, "not-a-hash")]
    [InlineData(6, "S-1-5-21-1-2-3-01001")]
    public void NonCanonicalOrUnsafeArgumentIsRejected(int index, string value)
    {
        var args = WorkerLaunchArguments.Encode(Descriptor()); args[index] = value;
        Assert.Throws<ArgumentException>(() => WorkerLaunchArguments.Decode(args));
    }
    [Fact]
    public void SameAccountExtraArgumentAndNulAreRejected()
    {
        var args = WorkerLaunchArguments.Encode(Descriptor()); args[6] = args[3];
        Assert.Throws<ArgumentException>(() => WorkerLaunchArguments.Decode(args));
        args = WorkerLaunchArguments.Encode(Descriptor());
        Assert.Throws<ArgumentException>(() => WorkerLaunchArguments.Decode([.. args, "extra"]));
        args[4] += '\0'; Assert.Throws<ArgumentException>(() => WorkerLaunchArguments.Decode(args));
    }
}
