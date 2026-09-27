namespace JTS.WindowsCompanion.Tests;

internal sealed class ManualTimeProvider : TimeProvider
{
    private readonly object _sync = new();
    private readonly List<ManualTimer> _timers = [];
    private DateTimeOffset _utcNow;

    public ManualTimeProvider(DateTimeOffset utcNow)
    {
        _utcNow = utcNow;
    }

    public override DateTimeOffset GetUtcNow()
    {
        lock (_sync)
        {
            return _utcNow;
        }
    }

    public override ITimer CreateTimer(
        TimerCallback callback,
        object? state,
        TimeSpan dueTime,
        TimeSpan period)
    {
        ArgumentNullException.ThrowIfNull(callback);
        var timer = new ManualTimer(this, callback, state);
        lock (_sync)
        {
            _timers.Add(timer);
            ChangeTimer(timer, dueTime, period);
        }

        return timer;
    }

    public void Advance(TimeSpan duration)
    {
        if (duration < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(duration));
        }

        lock (_sync)
        {
            _utcNow += duration;
        }

        while (true)
        {
            ManualTimer[] due;
            lock (_sync)
            {
                due = _timers
                    .Where(timer => !timer.IsDisposed && timer.DueAt is { } dueAt && dueAt <= _utcNow)
                    .ToArray();
                foreach (var timer in due)
                {
                    timer.MarkFired(_utcNow);
                }
            }

            if (due.Length == 0)
            {
                return;
            }

            foreach (var timer in due)
            {
                timer.Invoke();
            }
        }
    }

    private bool ChangeTimer(ManualTimer timer, TimeSpan dueTime, TimeSpan period)
    {
        if (timer.IsDisposed)
        {
            return false;
        }

        ValidateTimeout(dueTime, nameof(dueTime));
        ValidateTimeout(period, nameof(period));
        timer.DueAt = dueTime == Timeout.InfiniteTimeSpan ? null : _utcNow + dueTime;
        timer.Period = period;
        return true;
    }

    private void RemoveTimer(ManualTimer timer)
    {
        lock (_sync)
        {
            timer.IsDisposed = true;
            timer.DueAt = null;
            _timers.Remove(timer);
        }
    }

    private static void ValidateTimeout(TimeSpan value, string parameterName)
    {
        if (value < TimeSpan.Zero && value != Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(parameterName);
        }
    }

    private sealed class ManualTimer : ITimer
    {
        private readonly ManualTimeProvider _owner;
        private readonly TimerCallback _callback;
        private readonly object? _state;

        public ManualTimer(ManualTimeProvider owner, TimerCallback callback, object? state)
        {
            _owner = owner;
            _callback = callback;
            _state = state;
        }

        public DateTimeOffset? DueAt { get; set; }

        public TimeSpan Period { get; set; }

        public bool IsDisposed { get; set; }

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            lock (_owner._sync)
            {
                return _owner.ChangeTimer(this, dueTime, period);
            }
        }

        public void Dispose() => _owner.RemoveTimer(this);

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }

        public void MarkFired(DateTimeOffset now)
        {
            DueAt = Period == Timeout.InfiniteTimeSpan ? null : now + Period;
        }

        public void Invoke() => _callback(_state);
    }
}
