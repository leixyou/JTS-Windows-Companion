using System.Text;
using System.Text.Json;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.Execution;

internal sealed class PowerShellRequest
{
    internal const string Kind = "powershell.v1";
    internal string Script { get; }
    internal string WorkingDirectory { get; }
    private PowerShellRequest(string script, string workingDirectory)
        => (Script, WorkingDirectory) = (script, workingDirectory);

    internal static PowerShellRequest Parse(JobBinding binding, ReadOnlyMemory<byte> payload)
    {
        if (binding.Kind != Kind || payload.Length is 0 or > 65_536 || JobBinding.Hash(payload.Span) != binding.PayloadSha256)
            throw Invalid();
        try
        {
            using var document = JsonDocument.Parse(payload, new JsonDocumentOptions { MaxDepth = 2 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw Invalid();
            var fields = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
                if (!fields.Add(property.Name) || property.Name is not ("version" or "script" or "workingDirectory")) throw Invalid();
            if (fields.Count != 3 || !root.GetProperty("version").TryGetInt32(out var version) || version != 1) throw Invalid();
            var script = root.GetProperty("script").GetString();
            var directory = root.GetProperty("workingDirectory").GetString();
            if (string.IsNullOrWhiteSpace(script) || script.Contains('\0') || Encoding.UTF8.GetByteCount(script) > 48 * 1024
                || (directory != "." && !IsLocalDirectory(directory))) throw Invalid();
            return new PowerShellRequest(script, directory!);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or FormatException or ArgumentException)
        { throw Invalid(); } // Never surface JSON snippets or script contents.
    }

    internal static bool IsLocalDirectory(string? path)
    {
        if (path is not { Length: >= 3 and <= 240 } || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\') return false;
        if (path.AsSpan(2).IndexOfAny(':', '/', '\0') >= 0 || path.Any(c => c < 32 || c is '"' or '<' or '>' or '|' or '?' or '*')) return false;
        var parts = path[3..].TrimEnd('\\').Split('\\');
        if (parts.Length == 1 && parts[0].Length == 0) return true;
        return parts.All(p => p.Length > 0 && p is not ("." or "..") && !p.EndsWith('.') && !p.EndsWith(' '));
    }

    private static JobRuntimeException Invalid() => new("JOB_POWERSHELL_PAYLOAD_INVALID");
    public override string ToString() => "PowerShellRequest (contents omitted)";
}
