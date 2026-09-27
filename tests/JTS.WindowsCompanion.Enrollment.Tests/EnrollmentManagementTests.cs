using System.Text;
using System.IO.Pipes;
using Xunit;

namespace JTS.WindowsCompanion.Enrollment.Tests;

public sealed class EnrollmentManagementTests
{
    [Theory]
    [InlineData(false, true, true, 1, 1, true)]
    [InlineData(true, true, true, 1, 1, false)]
    [InlineData(false, false, true, 1, 1, false)]
    [InlineData(false, true, false, 1, 1, false)]
    [InlineData(false, true, true, 0, 0, false)]
    [InlineData(false, true, true, 1, 2, false)]
    public void LocalAccessRequiresActualInteractiveElevatedAdministrator(bool system, bool admin, bool elevated, int tokenSession, int processSession, bool accepted)
    {
        var failure = Record.Exception(() => EnrollmentCallerPolicy.Require("S-1-5-21-123-456-789-500", system, admin, elevated, tokenSession, processSession));
        if (accepted) Assert.Null(failure); else Assert.IsType<EnrollmentException>(failure);
    }
    [Theory]
    [InlineData("{\"version\":1,\"operation\":\"execute\",\"code\":null,\"invitationId\":null}")]
    [InlineData("{\"version\":1,\"operation\":\"status\",\"code\":\"secret\",\"invitationId\":null}")]
    [InlineData("{\"version\":1,\"operation\":\"status\",\"operation\":\"enroll\",\"code\":null,\"invitationId\":null}")]
    [InlineData("{\"version\":1,\"operation\":\"status\",\"code\":null,\"invitationId\":null,\"shell\":\"calc\"}")]
    public void ManagementProtocolRejectsCommandsDuplicatesAndUnknownFields(string json)
        => Assert.Throws<EnrollmentException>(() => EnrollmentManagementWire.Parse(Encoding.UTF8.GetBytes(json)));
    [Fact]
    public async Task ServerKeepsReplyUntilClientAcknowledgesReadingIt()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var name = "je-" + Guid.NewGuid().ToString("N")[..12];
        using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        var connected = server.WaitForConnectionAsync(timeout.Token);
        await client.ConnectAsync(timeout.Token); await connected;
        var reply = EnrollmentManagementWire.ReplyAsync(server, new { state = "bound" }, timeout.Token);
        var bytes = await EnrollmentManagementWire.ReadAsync(client, timeout.Token);
        Assert.Contains("bound", Encoding.UTF8.GetString(bytes)); Assert.False(reply.IsCompleted);
        await client.WriteAsync(new byte[] { 0xAC }, timeout.Token); await reply;
        var second = EnrollmentManagementWire.ReplyAsync(server, new { state = "idle" }, timeout.Token);
        Assert.Contains("idle", Encoding.UTF8.GetString(await EnrollmentManagementWire.ReceiveReplyAsync(client, timeout.Token)));
        await second;
    }
    [Fact]
    public async Task MissingAcknowledgementRemainsCancellable()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var name = "je-" + Guid.NewGuid().ToString("N")[..12];
        using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        var connected = server.WaitForConnectionAsync(); await client.ConnectAsync(); await connected;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => EnrollmentManagementWire.ReplyAsync(server, new { state = "idle" }, timeout.Token));
    }
    [Fact]
    public async Task ManagementFrameBoundIsCheckedBeforeAllocation()
    {
        using var input = new MemoryStream([0x7f, 0xff, 0xff, 0xff]);
        await Assert.ThrowsAsync<EnrollmentException>(() => EnrollmentManagementWire.ReadAsync(input, default));
    }
}
