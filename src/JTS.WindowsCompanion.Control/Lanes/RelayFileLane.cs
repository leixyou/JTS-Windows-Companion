using JTS.WindowsCompanion.Files;
using JTS.WindowsCompanion.Pairing;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Relay;

namespace JTS.WindowsCompanion.Control;

public sealed class RelayFileLane : ICompanionRelayLaneHandler, IAsyncDisposable
{
    private readonly DurableRelayPairingStore _pairings;
    private readonly SandboxedFileService _files;
    private readonly RelayFileUploads _uploads;
    private readonly RelayFileOperations _operations;
    private readonly SemaphoreSlim _operationsGate = new(1, 1);
    public RelayFileLane(DurableRelayPairingStore pairings, string sharedRoot, string privateSpoolRoot)
    {
        _pairings = pairings;
        var sandbox = new FileSandbox([new("shared", sharedRoot)]);
        _files = new(sandbox); _uploads = new(sandbox, _files, privateSpoolRoot);
        _operations = new(sandbox, _uploads);
    }
    public async Task ServeAsync(Stream stream, string ownerDeviceId, CancellationToken cancellationToken)
    {
        Guid? granted = null; var window = DateTimeOffset.UtcNow; var count = 0;
        while (await LaneRequest.ReadAsync(stream, cancellationToken).ConfigureAwait(false) is { } request)
        {
            if (DateTimeOffset.UtcNow - window >= TimeSpan.FromMinutes(1)) { window = DateTimeOffset.UtcNow; count = 0; }
            if (++count > 2400) throw new ControlProtocolException("FILE_RATE_LIMIT");
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); deadline.CancelAfter(TimeSpan.FromSeconds(30));
            try
            {
                if (granted is not null && granted != request.GrantId) throw new ControlProtocolException("LANE_GRANT_REQUIRED");
                await LaneRequest.AuthorizeAsync(_pairings, ownerDeviceId, RelayLane.File, request.GrantId, deadline.Token).ConfigureAwait(false);
                object result;
                if (granted is null) { request.RequireOpen("file.open"); granted = request.GrantId; result = new { ready = true }; }
                else
                {
                    await _operationsGate.WaitAsync(deadline.Token).ConfigureAwait(false);
                    try { result = await _operations.ExecuteAsync(ownerDeviceId, request.GrantId, request.Operation, request.Parameters, deadline.Token).ConfigureAwait(false); }
                    finally { _operationsGate.Release(); }
                }
                await LaneRequest.AuthorizeAsync(_pairings, ownerDeviceId, RelayLane.File, request.GrantId, deadline.Token).ConfigureAwait(false);
                await request.ReplyAsync(stream, result, null, deadline.Token).ConfigureAwait(false);
            }
            catch (Exception error) when (error is ControlProtocolException or FileSandboxException or CompanionProtocolException or IOException or UnauthorizedAccessException)
            {
                var code = error switch { ControlProtocolException e => e.Code, FileSandboxException e => e.Code,
                    CompanionProtocolException e => e.Code, _ => "FILE_OPERATION_FAILED" };
                await request.ReplyAsync(stream, null, code, deadline.Token).ConfigureAwait(false);
                if (granted is null || code == "LANE_GRANT_REQUIRED") return;
            }
        }
    }
    public async ValueTask DisposeAsync() { await _uploads.DisposeAsync().ConfigureAwait(false); _files.Dispose(); _operationsGate.Dispose(); }
}
