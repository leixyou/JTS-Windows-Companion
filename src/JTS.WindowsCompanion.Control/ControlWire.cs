using System.Buffers.Binary;
using System.Text.Json;

namespace JTS.WindowsCompanion.Control;

internal static class ControlWire
{
    internal const int MaximumFrameBytes = 96 * 1024;
    internal const int MaximumPayloadBytes = 64 * 1024;
    internal const int MaximumOutputChunkBytes = 32 * 1024;
    internal static string Name(ControlOperation op) => op switch
    {
        ControlOperation.Status => "device.status", ControlOperation.Submit => "job.submit",
        ControlOperation.Get => "job.get", ControlOperation.Cancel => "job.cancel", ControlOperation.Output => "job.output",
        _ => throw new ControlProtocolException("CONTROL_OPERATION_UNSUPPORTED"),
    };
    internal static ControlOperation Operation(string name) => name switch
    {
        "device.status" => ControlOperation.Status, "job.submit" => ControlOperation.Submit,
        "job.get" => ControlOperation.Get, "job.cancel" => ControlOperation.Cancel, "job.output" => ControlOperation.Output,
        _ => throw new ControlProtocolException("CONTROL_OPERATION_UNSUPPORTED"),
    };

    internal static async Task<byte[]?> ReadAsync(Stream stream, CancellationToken token)
    {
        var header = new byte[4];
        if (await stream.ReadAsync(header.AsMemory(0, 1), token).ConfigureAwait(false) == 0) return null;
        await stream.ReadExactlyAsync(header.AsMemory(1), token).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadUInt32BigEndian(header);
        if (length is 0 or > MaximumFrameBytes) throw new ControlProtocolException("CONTROL_FRAME_LIMIT");
        var body = new byte[length];
        await stream.ReadExactlyAsync(body, token).ConfigureAwait(false);
        return body;
    }

    internal static async Task WriteAsync(Stream stream, byte[] body, CancellationToken token)
    {
        if (body.Length is 0 or > MaximumFrameBytes) throw new ControlProtocolException("CONTROL_FRAME_LIMIT");
        var header = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(header, (uint)body.Length);
        await stream.WriteAsync(header, token).ConfigureAwait(false);
        for (var offset = 0; offset < body.Length; offset += 16 * 1024)
            await stream.WriteAsync(body.AsMemory(offset, Math.Min(16 * 1024, body.Length - offset)), token).ConfigureAwait(false);
        await stream.FlushAsync(token).ConfigureAwait(false);
    }

    internal static JsonDocument Parse(byte[] bytes)
    {
        try
        {
            var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 });
            try { Unique(doc.RootElement); return doc; }
            catch { doc.Dispose(); throw; }
        }
        catch (JsonException) { throw new ControlProtocolException("CONTROL_REQUEST_INVALID"); }
    }
    private static void Unique(JsonElement node)
    {
        if (node.ValueKind == JsonValueKind.Object)
        {
            var keys = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in node.EnumerateObject())
            { if (!keys.Add(property.Name)) throw new JsonException(); Unique(property.Value); }
        }
        else if (node.ValueKind == JsonValueKind.Array) foreach (var value in node.EnumerateArray()) Unique(value);
    }
    internal static void Fields(JsonElement node, params string[] fields)
    {
        if (node.ValueKind != JsonValueKind.Object || !node.EnumerateObject().Select(p => p.Name).Order().SequenceEqual(fields.Order()))
            throw new ControlProtocolException("CONTROL_REQUEST_INVALID");
    }
    internal static string Text(JsonElement node, string key, int maximum)
    {
        if (!node.TryGetProperty(key, out var value) || value.ValueKind != JsonValueKind.String
            || value.GetString() is not { Length: > 0 } text || text.Length > maximum || text.Contains('\0'))
            throw new ControlProtocolException("CONTROL_REQUEST_INVALID");
        return text;
    }
    internal static Guid Id(JsonElement node, string key)
    {
        var text = Text(node, key, 36);
        if (!Guid.TryParseExact(text, "D", out var id) || id == Guid.Empty || id.ToString("D") != text)
            throw new ControlProtocolException("CONTROL_REQUEST_INVALID");
        return id;
    }
    internal static long Integer(JsonElement node, string key)
    {
        if (!node.TryGetProperty(key, out var value) || value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out var result))
            throw new ControlProtocolException("CONTROL_REQUEST_INVALID");
        return result;
    }
    internal static bool Boolean(JsonElement node, string key)
    {
        if (!node.TryGetProperty(key, out var value) || value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            throw new ControlProtocolException("CONTROL_REQUEST_INVALID");
        return value.GetBoolean();
    }
}
