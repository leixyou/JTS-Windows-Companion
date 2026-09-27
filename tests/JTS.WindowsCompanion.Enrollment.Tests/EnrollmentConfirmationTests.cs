using Xunit;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace JTS.WindowsCompanion.Enrollment.Tests;

public sealed class EnrollmentConfirmationTests
{
    [Fact]
    public async Task CancelledReceiptMayRetainItsHistoricalSignedConfirmation()
    {
        using var f = new EnrollmentFixture(); await f.Coordinator.EnrollAsync(f.Code); await f.Coordinator.StepAsync(); f.Confirm();
        var original = f.Relay.Receipt with { State = "cancelled" };
        var bytes = JsonSerializer.SerializeToUtf8Bytes(original, new JsonSerializerOptions {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });
        var parsed = EnrollmentRelayClient.Parse(bytes);
        Assert.Equal("cancelled", parsed.State); Assert.Equal(original.Confirmation, parsed.Confirmation);
        f.Relay.Receipt = parsed; await f.Coordinator.StepAsync();
        Assert.Equal("cancelled", (await f.Coordinator.StatusAsync()).State); Assert.Empty(f.Grants.ListLocally());
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RelayCannotPromoteOwnClaimToBoundWithoutControllerSignature(bool afterExpiry)
    {
        using var f = new EnrollmentFixture(); await f.Coordinator.EnrollAsync(f.Code); await f.Coordinator.StepAsync();
        f.Relay.Receipt = f.Relay.Receipt with { State = "bound" };
        if (afterExpiry) f.Clock.Now = f.Clock.Now.AddHours(2);
        await f.Coordinator.StepAsync();
        Assert.Equal("faulted", (await f.Coordinator.StatusAsync()).State);
        Assert.Empty(f.Grants.ListLocally()); Assert.Empty(f.Pairings.ListLocally()); Assert.Equal(0, f.ActivationCalls);
    }
    [Theory]
    [InlineData("origin")]
    [InlineData("peer")]
    [InlineData("controller")]
    [InlineData("claim")]
    [InlineData("invitation")]
    [InlineData("issued")]
    [InlineData("expiry")]
    [InlineData("signature")]
    public async Task ConfirmationCannotBeSubstituted(string field)
    {
        using var f = new EnrollmentFixture(); await f.Coordinator.EnrollAsync(f.Code); await f.Coordinator.StepAsync(); f.Confirm();
        var c = f.Relay.Receipt.Confirmation!;
        c = field switch {
            "origin" => c with { RelayOrigin = "https://other.example.test" },
            "peer" => c with { PeerDeviceId = new string('a', 64) },
            "controller" => c with { ControllerDeviceId = new string('a', 64) },
            "claim" => c with { ClaimHash = new string('a', 64) },
            "invitation" => c with { InvitationId = Guid.NewGuid().ToString("D") },
            "issued" => c with { ConfirmedAtUnixSeconds = c.ConfirmedAtUnixSeconds - 1 },
            "expiry" => c with { ExpiresAtUnixSeconds = c.ExpiresAtUnixSeconds + 1 },
            _ => c with { SignatureBase64 = Convert.ToBase64String(new byte[64]) },
        };
        f.Relay.Receipt = f.Relay.Receipt with { Confirmation = c }; await f.Coordinator.StepAsync();
        Assert.Equal("faulted", (await f.Coordinator.StatusAsync()).State); Assert.Empty(f.Grants.ListLocally()); Assert.Empty(f.Pairings.ListLocally());
    }
}
