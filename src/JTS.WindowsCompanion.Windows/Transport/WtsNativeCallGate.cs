namespace JTS.WindowsCompanion.Windows.Transport;

/// <summary>WTS Read/Write are not thread safe on a shared channel handle.</summary>
internal sealed class WtsNativeCallGate : IDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);

    internal T Invoke<T>(Func<T> operation, CancellationToken cancellationToken)
    {
        _gate.Wait(cancellationToken);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            return operation();
        }
        finally { _gate.Release(); }
    }

    internal async ValueTask<T> InvokeAsync<T>(Func<T> operation, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            return operation();
        }
        finally { _gate.Release(); }
    }

    public void Dispose() => _gate.Dispose();
}
