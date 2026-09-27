using System.Text.Json;
using System.Text.Json.Serialization;

namespace JTS.WindowsCompanion.Protocol;

public sealed record CompanionRequest(
    int ProtocolVersion,
    Guid RequestId,
    string Method,
    long? DeadlineUnixMilliseconds,
    string? IdempotencyKey,
    ulong? ExpectedStateRevision,
    JsonElement Parameters);

public sealed record CompanionError(string Code, string Message, bool Retryable = false);

public sealed record CompanionResponse(
    int ProtocolVersion,
    Guid RequestId,
    bool Success,
    JsonElement? Result,
    CompanionError? Error)
{
    public static CompanionResponse Ok(Guid requestId, object? result) => new(
        CompanionProtocol.CurrentVersion,
        requestId,
        true,
        ControlMessageSerializer.ToElement(result),
        null);

    public static CompanionResponse Fail(Guid requestId, string code, string message, bool retryable = false) => new(
        CompanionProtocol.CurrentVersion,
        requestId,
        false,
        null,
        new CompanionError(code, message, retryable));
}

public static class ControlMessageSerializer
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNameCaseInsensitive = false,
        WriteIndented = false,
    };

    public static byte[] Serialize<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value, Options);

    public static T Deserialize<T>(ReadOnlySpan<byte> payload)
    {
        try
        {
            return JsonSerializer.Deserialize<T>(payload, Options)
                ?? throw new CompanionProtocolException("JSON_INVALID", "The control payload is empty.");
        }
        catch (JsonException exception)
        {
            throw new CompanionProtocolException("JSON_INVALID", $"The control payload is invalid: {exception.Path ?? "$"}.");
        }
    }

    public static JsonElement ToElement(object? value) => JsonSerializer.SerializeToElement(value, Options);
}
