using System.Text.Json;
using JTS.WindowsCompanion.Files;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Transfers;

namespace JTS.WindowsCompanion.Control;

// Upload state survives a TLS reconnect, remains bound to exact owner+grant, and never trusts a client spool path.
internal sealed class RelayFileUploads(FileSandbox sandbox, SandboxedFileService files, string spoolRoot) : IAsyncDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<(string Owner, Guid Grant), UploadSession> _sessions = [];
    internal async Task<object> ExecuteAsync(string owner, Guid grant, string operation, JsonElement p, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            foreach (var key in _sessions.Where(item => item.Value.Touched < DateTimeOffset.UtcNow.AddMinutes(-15)).Select(item => item.Key).ToArray())
            { await _sessions[key].Transfers.DisposeAsync().ConfigureAwait(false); _sessions.Remove(key); }
            if (!_sessions.TryGetValue((owner, grant), out var session))
            {
                if (operation != "file.write.begin") throw RelayFileOperations.Error("TRANSFER_NOT_FOUND");
                if (_sessions.Count >= 16) throw RelayFileOperations.Error("TRANSFER_CONCURRENCY_LIMIT");
                session = new(new BinaryTransferCoordinator(spoolRoot)); _sessions.Add((owner, grant), session);
            }
            session.Touched = DateTimeOffset.UtcNow;
            var id = ControlWire.Id(p, "transferId");
            if (operation == "file.write.begin")
            {
                ControlWire.Fields(p, "transferId", "rootId", "path", "totalBytes", "sha256", "overwrite");
                var root = ControlWire.Text(p, "rootId", 64); var path = RelayFileOperations.PathText(p, "path");
                var destination = sandbox.Resolve(root, path, allowMissingLeaf: true); RelayFileOperations.Writable(destination);
                var total = ControlWire.Integer(p, "totalBytes"); var sha = ControlWire.Text(p, "sha256", 64);
                if (total < 0 || total > destination.Root.MaximumFileBytes || sha.Length != 64 || sha.Any(c => !"0123456789abcdef".Contains(c)))
                    throw RelayFileOperations.Error("TRANSFER_METADATA_INVALID");
                var binding = new UploadBinding(root, path, total, sha, ControlWire.Boolean(p, "overwrite"));
                if (session.Bindings.TryGetValue(id, out var existing) && existing.Binding != binding)
                    throw RelayFileOperations.Error("TRANSFER_ID_CONFLICT");
                if (existing?.Result is not null) return Descriptor(id, binding, binding.TotalBytes);
                if (existing is null)
                {
                    // Completed receipts are bounded separately from in-progress transfer capacity.
                    if (session.Bindings.Count >= 128) throw RelayFileOperations.Error("TRANSFER_RECEIPT_LIMIT");
                    session.Bindings.Add(id, new(binding));
                }
                return await BeginAsync(session, id, binding, token).ConfigureAwait(false);
            }
            if (!session.Bindings.TryGetValue(id, out var state)) throw RelayFileOperations.Error("TRANSFER_NOT_FOUND");
            if (operation == "file.write.chunk")
            {
                ControlWire.Fields(p, "transferId", "offset", "dataBase64", "final");
                if (state.Result is not null) throw RelayFileOperations.Error("TRANSFER_ALREADY_COMMITTED");
                var text = p.GetProperty("dataBase64").GetString() ?? throw RelayFileOperations.Error("TRANSFER_CHUNK_INVALID");
                if (text.Length > 43692) throw RelayFileOperations.Error("TRANSFER_CHUNK_TOO_LARGE");
                byte[] data; try { data = Convert.FromBase64String(text); } catch (FormatException) { throw RelayFileOperations.Error("TRANSFER_CHUNK_INVALID"); }
                if (data.Length > RelayFileOperations.ChunkBytes || Convert.ToBase64String(data) != text) throw RelayFileOperations.Error("TRANSFER_CHUNK_INVALID");
                await session.Transfers.AcceptUploadChunkAsync(new(id, ControlWire.Integer(p, "offset"), ControlWire.Boolean(p, "final"), data), token).ConfigureAwait(false);
                var descriptor = JsonSerializer.SerializeToElement(await BeginAsync(session, id, state.Binding, token).ConfigureAwait(false));
                return new { transferId = id, nextOffset = descriptor.GetProperty("nextOffset").GetInt64() };
            }
            ControlWire.Fields(p, "transferId");
            if (state.Result is not null) return state.Result;
            await session.Transfers.FinalizeUploadAsync(p, token).ConfigureAwait(false);
            var b = state.Binding;
            var verified = await session.Transfers.GetValidatedUploadAsync(id, "relay.file", b.TotalBytes, b.Sha256, token).ConfigureAwait(false);
            var written = await files.ImportBinaryAsync(new(b.RootId, b.Path, verified.FilePath, b.TotalBytes, b.Sha256,
                sandbox.Roots.Single(r => r.Id == b.RootId).MaximumFileBytes, b.Overwrite), token).ConfigureAwait(false);
            state.Result = new { name = written.Name, path = written.RelativePath.Replace('\\', '/'), isDirectory = false,
                size = written.Length, modifiedAtUnixMilliseconds = written.LastWriteTimeUtc.ToUnixTimeMilliseconds(), sha256 = written.Sha256!.ToLowerInvariant() };
            await session.Transfers.ReleaseAsync(id, CancellationToken.None).ConfigureAwait(false);
            return state.Result;
        }
        finally { _gate.Release(); }
    }
    private static async Task<object> BeginAsync(UploadSession session, Guid id, UploadBinding b, CancellationToken token)
    {
        var descriptor = JsonSerializer.SerializeToElement(await session.Transfers.BeginUploadAsync(JsonSerializer.SerializeToElement(new
        { transferId = id, purpose = "relay.file", totalBytes = b.TotalBytes, sha256 = b.Sha256 }), token).ConfigureAwait(false));
        return Descriptor(id, b, descriptor.GetProperty("nextOffset").GetInt64());
    }
    private static object Descriptor(Guid id, UploadBinding b, long nextOffset)
        => new { transferId = id, nextOffset, totalBytes = b.TotalBytes, sha256 = b.Sha256 };
    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try { foreach (var session in _sessions.Values) await session.Transfers.DisposeAsync().ConfigureAwait(false); _sessions.Clear(); }
        finally { _gate.Release(); _gate.Dispose(); }
    }
    private sealed record UploadBinding(string RootId, string Path, long TotalBytes, string Sha256, bool Overwrite);
    private sealed class UploadState(UploadBinding binding) { internal UploadBinding Binding = binding; internal object? Result; }
    private sealed class UploadSession(BinaryTransferCoordinator transfers)
    { internal BinaryTransferCoordinator Transfers = transfers; internal DateTimeOffset Touched = DateTimeOffset.UtcNow; internal Dictionary<Guid, UploadState> Bindings = []; }
}
