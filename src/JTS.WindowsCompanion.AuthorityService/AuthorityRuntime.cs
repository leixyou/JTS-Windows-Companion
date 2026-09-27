using JTS.WindowsCompanion.Control;

namespace JTS.WindowsCompanion.AuthorityService;

internal interface IAuthorityRuntime : IAsyncDisposable
{
    DateTimeOffset IdentityExpiresAt { get; }
    Task RunAsync(CancellationToken token);
}

// Keep protected resources leased until the control host confirms drain. Never release beneath a live executor.
internal sealed class AuthorityRuntime(DateTimeOffset expiry, Func<CancellationToken, Task> run,
    Func<ValueTask> drain, IReadOnlyList<IDisposable> resources) : IAuthorityRuntime
{
    private readonly SemaphoreSlim _disposeGate = new(1, 1);
    private bool _disposed;
    public DateTimeOffset IdentityExpiresAt => expiry;
    public Task RunAsync(CancellationToken token)
    { ObjectDisposedException.ThrowIf(_disposed, this); return run(token); }
    public async ValueTask DisposeAsync()
    {
        await _disposeGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_disposed) return;
            await drain().ConfigureAwait(false); // An uncertain drain retains every resource until retry/process exit.
            _disposed = true;
            Exception? failure = null;
            foreach (var resource in resources.Reverse())
                try { resource.Dispose(); } catch (Exception error) { failure ??= error; }
            if (failure is not null) throw new AuthorityException("AUTHORITY_RESOURCE_RELEASE_FAILED");
        }
        finally { _disposeGate.Release(); }
    }
    internal static AuthorityRuntime Own(CompanionRelayControlService service, DateTimeOffset expiry, IReadOnlyList<IDisposable> resources)
        => new(expiry, service.RunAsync, service.DisposeAsync, resources);
}
