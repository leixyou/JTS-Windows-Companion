using JTS.WindowsCompanion.Agent;

namespace JTS.WindowsCompanion.Transfers;

public static class BinaryTransferMethodRegistrar
{
    public static void Register(CompanionRequestRouter router, BinaryTransferCoordinator transfers)
    {
        ArgumentNullException.ThrowIfNull(router);
        ArgumentNullException.ThrowIfNull(transfers);
        router.Register("transfer.begin", (request, cancellationToken) =>
            Wrap(transfers.BeginUploadAsync(request.Parameters, cancellationToken)));
        router.Register("transfer.finalize", (request, cancellationToken) =>
            Wrap(transfers.FinalizeUploadAsync(request.Parameters, cancellationToken)));
        router.Register("transfer.download", (request, cancellationToken) =>
            Wrap(transfers.SendDownloadAsync(request.Parameters, cancellationToken)));
        router.Register("transfer.release", (request, cancellationToken) =>
            Wrap(transfers.ReleaseAsync(request.Parameters, cancellationToken)));
    }

    private static async ValueTask<object?> Wrap(ValueTask<object> operation) =>
        await operation.ConfigureAwait(false);
}
