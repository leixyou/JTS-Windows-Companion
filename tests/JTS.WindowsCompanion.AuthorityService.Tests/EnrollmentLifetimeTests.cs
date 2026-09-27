using Xunit;

namespace JTS.WindowsCompanion.AuthorityService.Tests;

public sealed class EnrollmentLifetimeTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedEnrollmentComponentCancelsAndObservesRunningControl(bool synchronous)
    {
        var stopped = false;
        async Task Control(CancellationToken token)
        { try { await Task.Delay(Timeout.Infinite, token); } finally { stopped = true; } }
        Task Failed(CancellationToken token) => synchronous ? throw new IOException("fixture") : Task.FromException(new IOException("fixture"));
        await Assert.ThrowsAsync<IOException>(() => AuthorityRuntime.RunTogetherAsync([Control, Failed], default));
        Assert.True(stopped);
    }
    [Fact]
    public async Task UnexpectedManagementCompletionStopsEveryComponent()
    {
        var stopped = false;
        async Task Control(CancellationToken token)
        { try { await Task.Delay(Timeout.Infinite, token); } finally { stopped = true; } }
        await Assert.ThrowsAsync<AuthorityException>(() => AuthorityRuntime.RunTogetherAsync([Control, _ => Task.CompletedTask], default));
        Assert.True(stopped);
    }
}
