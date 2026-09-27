using System.Buffers.Binary;
using System.Text.Json;

namespace JTS.WindowsCompanion.Enrollment;

internal sealed record EnrollmentManagementRequest(int Version, string Operation, string? Code, Guid? InvitationId)
{ public override string ToString() => "EnrollmentManagementRequest (secret omitted)"; }
internal static class EnrollmentManagementWire
{
    internal const string PipeName = "JTSCompanionEnrollment25";
    internal static async Task<byte[]> ReadAsync(Stream input, CancellationToken token)
    {
        var header = new byte[4]; await input.ReadExactlyAsync(header, token).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadUInt32BigEndian(header);
        if (length is < 1 or > 8192) throw new EnrollmentException("ENROLLMENT_REQUEST_INVALID");
        var bytes = new byte[length]; await input.ReadExactlyAsync(bytes, token).ConfigureAwait(false); return bytes;
    }
    internal static async Task WriteAsync<T>(Stream output, T value, CancellationToken token)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        if (bytes.Length > 8192) throw new EnrollmentException("ENROLLMENT_REQUEST_INVALID");
        var header = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(header, (uint)bytes.Length);
        await output.WriteAsync(header, token).ConfigureAwait(false); await output.WriteAsync(bytes, token).ConfigureAwait(false);
        await output.FlushAsync(token).ConfigureAwait(false);
    }
    internal static async Task<byte[]> ReceiveReplyAsync(Stream pipe, CancellationToken token)
    {
        var bytes = await ReadAsync(pipe, token).ConfigureAwait(false);
        await pipe.WriteAsync(new byte[] { 0xAC }, token).ConfigureAwait(false);
        await pipe.FlushAsync(token).ConfigureAwait(false);
        return bytes;
    }
    internal static async Task ReplyAsync<T>(Stream pipe, T value, CancellationToken token)
    {
        await WriteAsync(pipe, value, token).ConfigureAwait(false);
        // DisconnectNamedPipe discards unread bytes. A bounded acknowledgement avoids blocking FlushFileBuffers.
        var ack = new byte[1]; await pipe.ReadExactlyAsync(ack, token).ConfigureAwait(false);
        if (ack[0] != 0xAC) throw Invalid();
    }
    internal static EnrollmentManagementRequest Parse(byte[] bytes)
    {
        try
        {
            using var doc = JsonDocument.Parse(bytes); var p = doc.RootElement;
            EnrollmentCrypto.Fields(p, "version", "operation", "code", "invitationId");
            if (p.GetProperty("version").GetInt32() != 1) throw Invalid();
            var operation = p.GetProperty("operation").GetString(); var code = p.GetProperty("code").GetString();
            var value = p.GetProperty("invitationId"); Guid? id = value.ValueKind == JsonValueKind.Null ? null : value.GetGuid();
            if (operation == "status" && code is null && id is null) return new(1, operation, null, null);
            if (operation == "enroll" && code is { Length: >= 1 and <= 4096 } && id is null) return new(1, operation, code, null);
            if (operation == "revoke" && code is null && id is { } nonempty && nonempty != Guid.Empty) return new(1, operation, null, id);
            throw Invalid();
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or FormatException or KeyNotFoundException) { throw Invalid(); }
    }
    private static EnrollmentException Invalid() => new("ENROLLMENT_REQUEST_INVALID");
}

internal static class EnrollmentCallerPolicy
{
    internal static void Require(string? sid, bool system, bool administrator, bool elevated, int tokenSession, int processSession)
    {
        if (sid is null || !sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) || system || !administrator || !elevated
            || tokenSession < 1 || tokenSession != processSession) throw new EnrollmentException("ENROLLMENT_ACCESS_DENIED");
    }
}
