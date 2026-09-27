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
    internal static AuthorityRuntime Own(CompanionRelayControlService service, DateTimeOffset expiry, IReadOnlyList<IDisposable> resources,
        params Func<CancellationToken, Task>[] additional)
        => new(expiry, token => RunTogetherAsync([service.RunAsync, .. additional], token), service.DisposeAsync, resources);
    internal static async Task RunTogetherAsync(Func<CancellationToken, Task>[] components, CancellationToken token)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token);
        var tasks = new List<Task>();
        try
        {
            foreach (var run in components) tasks.Add(run(linked.Token));
            var first = await Task.WhenAny(tasks).ConfigureAwait(false);
            await first.ConfigureAwait(false);
            if (!token.IsCancellationRequested) throw new AuthorityException("AUTHORITY_COMPONENT_STOPPED");
        }
        finally
        {
            linked.Cancel();
            try { await Task.WhenAll(tasks).ConfigureAwait(false); } catch { /* Every component observed; propagate the first failure. */ }
        }
    }
}
