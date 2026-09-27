namespace JTS.WindowsCompanion.AuthorityService;

internal enum AuthorityPhase { Starting, Running, Stopping, Stopped }
internal sealed record AuthorityStatus(AuthorityPhase Phase, int ExitCode);
internal sealed record AuthorityTiming(TimeSpan ExpiryLead, TimeSpan ExpiryPoll, TimeSpan DrainTimeout)
{
    internal static AuthorityTiming Default { get; } = new(TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(1), TimeSpan.FromSeconds(15));
}

/// <summary>SCM lifecycle independent of relay availability. Exit 71 never means confirmed process-tree stop.</summary>
internal sealed class AuthorityLifetime(Action<AuthorityStatus> report, TimeProvider? clock = null, AuthorityTiming? timing = null)
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly AuthorityTiming _timing = timing ?? AuthorityTiming.Default;
    private int _used;
    internal async Task<int> RunAsync(Func<CancellationToken, IAuthorityRuntime> factory, CancellationToken stop)
    {
        if (Interlocked.Exchange(ref _used, 1) != 0) throw new AuthorityException("AUTHORITY_ALREADY_STARTED");
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(stop);
        IAuthorityRuntime? runtime = null; Task? monitor = null; var exit = 0; var expiring = 0;
        try
        {
            report(new(AuthorityPhase.Starting, 0)); stop.ThrowIfCancellationRequested();
            runtime = factory(linked.Token); stop.ThrowIfCancellationRequested();
            if (runtime.IdentityExpiresAt <= _clock.GetUtcNow() + _timing.ExpiryLead)
                throw new AuthorityException("AUTHORITY_IDENTITY_RENEWAL_REQUIRED");
            report(new(AuthorityPhase.Running, 0));
            monitor = WatchExpiryAsync(runtime.IdentityExpiresAt, linked.Token, () =>
            { Interlocked.Exchange(ref expiring, 1); linked.Cancel(); });
            var run = runtime.RunAsync(linked.Token);
            if (await Task.WhenAny(run, monitor).ConfigureAwait(false) == monitor)
                await monitor.ConfigureAwait(false); // Expiry watcher failure also stops admission.
            await run.ConfigureAwait(false);
            if (!linked.IsCancellationRequested) exit = 70; // Unexpected normal completion is not a running service.
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested) { }
        catch (AuthorityException error) when (error.Code == "AUTHORITY_IDENTITY_RENEWAL_REQUIRED") { exit = 72; }
        catch { exit = 70; }
        finally
        {
            try { linked.Cancel(); } catch { exit = 71; }
            try { report(new(AuthorityPhase.Stopping, exit)); } catch { exit = Math.Max(exit, 70); }
            if (monitor is not null)
                try { await monitor.ConfigureAwait(false); } catch (OperationCanceledException) { } catch { exit = 70; }
            if (runtime is not null)
                try { await runtime.DisposeAsync().AsTask().WaitAsync(_timing.DrainTimeout).ConfigureAwait(false); }
                catch { exit = 71; }
            if (exit == 0 && Volatile.Read(ref expiring) != 0) exit = 72;
            try { report(new(AuthorityPhase.Stopped, exit)); } catch { exit = Math.Max(exit, 70); }
        }
        return exit;
    }
    private async Task WatchExpiryAsync(DateTimeOffset expiry, CancellationToken token, Action expire)
    {
        while (true)
        {
            token.ThrowIfCancellationRequested();
            var remaining = expiry - _timing.ExpiryLead - _clock.GetUtcNow();
            if (remaining <= TimeSpan.Zero) { expire(); return; }
            await Task.Delay(remaining < _timing.ExpiryPoll ? remaining : _timing.ExpiryPoll, _clock, token).ConfigureAwait(false);
        }
    }
}
