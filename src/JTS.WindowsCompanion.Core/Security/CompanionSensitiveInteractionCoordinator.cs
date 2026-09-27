using JTS.WindowsCompanion.Protocol;

namespace JTS.WindowsCompanion.Security;

public enum CompanionSensitiveInteractionKind
{
    Pairing,
    ElevationPrompt,
    DesktopAutomation,
    ShellMutation,
    FileMutation,
    WorkerMutation,
    ManagedMutation,
}

/// <summary>
/// A fail-fast, process-local barrier for operations that can present a human
/// consent surface or mutate the interactive Windows session. It never queues
/// an AI action behind a prompt, because a delayed action could target a
/// different foreground window after the user responds.
/// </summary>
public sealed class CompanionSensitiveInteractionCoordinator
{
    private readonly object _sync = new();
    private ActiveInteraction? _active;
    private long _generation;

    public bool IsActive
    {
        get
        {
            lock (_sync)
            {
                return _active is not null;
            }
        }
    }

    public CompanionSensitiveInteractionKind? ActiveKind
    {
        get
        {
            lock (_sync)
            {
                return _active?.Kind;
            }
        }
    }

    public IDisposable Enter(CompanionSensitiveInteractionKind kind)
    {
        lock (_sync)
        {
            if (_active is not null)
            {
                throw new CompanionProtocolException(
                    "SENSITIVE_INTERACTION_ACTIVE",
                    "A human confirmation or another interactive Windows operation is already active.");
            }

            _generation = _generation == long.MaxValue ? 1 : _generation + 1;
            var generation = _generation;
            _active = new ActiveInteraction(generation, kind);
            return new Lease(this, generation);
        }
    }

    private void Release(long generation)
    {
        lock (_sync)
        {
            if (_active?.Generation == generation)
            {
                _active = null;
            }
        }
    }

    private sealed record ActiveInteraction(
        long Generation,
        CompanionSensitiveInteractionKind Kind);

    private sealed class Lease(
        CompanionSensitiveInteractionCoordinator owner,
        long generation) : IDisposable
    {
        private CompanionSensitiveInteractionCoordinator? _owner = owner;

        public void Dispose()
        {
            Interlocked.Exchange(ref _owner, null)?.Release(generation);
        }
    }
}
