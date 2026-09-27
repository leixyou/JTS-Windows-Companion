using JTS.WindowsCompanion.Protocol;

namespace JTS.WindowsCompanion.Transport;

public interface ICompanionChannel : IAsyncDisposable
{
    bool IsConnected { get; }

    ValueTask ConnectAsync(CancellationToken cancellationToken);

    ValueTask<CompanionFrame> ReceiveAsync(CancellationToken cancellationToken);

    ValueTask SendAsync(CompanionFrame frame, CancellationToken cancellationToken);
}
