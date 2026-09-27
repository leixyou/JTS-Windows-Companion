using System.Net;
using Xunit;

namespace JTS.WindowsCompanion.Enrollment.Tests;

public sealed class EnrollmentRelayClientTests
{
    [Fact]
    public async Task DeadlineIncludesBodyAfterSuccessfulHeaders()
    {
        using var body = new HangingBody();
        using var client = new EnrollmentRelayClient(new Uri("https://relay.example.test"), new ReplyHandler(body), TimeSpan.FromMilliseconds(100));
        using var code = EnrollmentCode.Parse(EnrollmentCryptoTests.ValidCode);
        var attempt = new EnrollmentAttempt(code.InvitationId, code.RelayOrigin, Convert.ToBase64String(code.Secret), "pending", DateTimeOffset.UtcNow);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.ExchangeAsync("offer", attempt, "", CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.True(body.ReadStarted); Assert.True(body.CancellationObserved);
    }

    [Fact]
    public async Task BrokenBodyTransportIsRetryableNetworkFailure()
    {
        using var body = new BrokenBody();
        using var client = new EnrollmentRelayClient(new Uri("https://relay.example.test"), new ReplyHandler(body), TimeSpan.FromSeconds(1));
        using var code = EnrollmentCode.Parse(EnrollmentCryptoTests.ValidCode);
        var attempt = new EnrollmentAttempt(code.InvitationId, code.RelayOrigin, Convert.ToBase64String(code.Secret), "pending", DateTimeOffset.UtcNow);
        var error = await Assert.ThrowsAsync<HttpRequestException>(() => client.ExchangeAsync("offer", attempt, "", CancellationToken.None));
        Assert.IsType<IOException>(error.InnerException);
    }
    private sealed class BrokenBody : MemoryStream
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => ValueTask.FromException<int>(new IOException("Connection interrupted"));
    }
    private sealed class ReplyHandler(Stream body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(body) };
            response.Content.Headers.ContentLength = 1024;
            return Task.FromResult(response);
        }
    }
    private sealed class HangingBody : MemoryStream
    {
        internal bool ReadStarted, CancellationObserved;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ReadStarted = true;
            try { await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); return 0; }
            catch (OperationCanceledException) { CancellationObserved = true; throw; }
        }
    }
}
