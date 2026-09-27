using JTS.WindowsCompanion.Windows.Automation;
using JTS.WindowsCompanion.Windows.Security;
using JTS.WindowsCompanion.Windows.Transport;

namespace JTS.WindowsCompanion.Tests;

public sealed class PlatformGuardTests
{
    [Fact]
    public async Task WindowsAdapters_FailClosedWhenBuiltOrRunOutsideWindows()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        await using var channel = new WtsDynamicVirtualChannel();
        await Assert.ThrowsAsync<PlatformNotSupportedException>(async () =>
            await channel.ConnectAsync(CancellationToken.None));
        Assert.Throws<PlatformNotSupportedException>(() =>
            new DpapiDataProtector().Protect("identity"u8, "entropy"u8));
        await Assert.ThrowsAsync<PlatformNotSupportedException>(async () =>
            await new WindowsUiAutomationService().SnapshotAsync(2, 100, CancellationToken.None));
    }
}
