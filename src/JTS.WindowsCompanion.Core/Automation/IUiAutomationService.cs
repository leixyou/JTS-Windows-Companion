namespace JTS.WindowsCompanion.Automation;

public sealed record UiaSelector(
    string? AutomationId = null,
    string? Name = null,
    string? ControlType = null,
    int? ProcessId = null)
{
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(AutomationId)
            && string.IsNullOrWhiteSpace(Name)
            && string.IsNullOrWhiteSpace(ControlType)
            && ProcessId is null)
        {
            throw new ArgumentException("At least one UI Automation selector field is required.");
        }

        if (ProcessId <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(ProcessId));
        }
    }

    public void ValidateForMutation()
    {
        Validate();
        if (ProcessId is null)
        {
            throw new ArgumentException(
                "UI Automation mutations require an explicit positive processId.",
                nameof(ProcessId));
        }

        if (string.IsNullOrWhiteSpace(AutomationId)
            && string.IsNullOrWhiteSpace(Name))
        {
            throw new ArgumentException(
                "UI Automation mutations require automationId or name in addition to processId.");
        }
    }
}

public sealed record UiaBounds(double X, double Y, double Width, double Height);

public sealed record UiaElement(
    string RuntimeId,
    string? AutomationId,
    string? Name,
    string ControlType,
    int ProcessId,
    bool IsEnabled,
    bool IsOffscreen,
    UiaBounds Bounds,
    IReadOnlyList<UiaElement> Children);

public sealed record UiaSnapshot(UiaElement Root, bool Truncated, int NodeCount);

public sealed record UiaEvent(
    string EventType,
    string RuntimeId,
    string? AutomationId,
    string? Name,
    DateTimeOffset Timestamp);

public interface IUiAutomationService
{
    ValueTask<UiaSnapshot> SnapshotAsync(int maximumDepth, int maximumNodes, CancellationToken cancellationToken);

    ValueTask<IReadOnlyList<UiaElement>> FindAsync(UiaSelector selector, int maximumResults, CancellationToken cancellationToken);

    ValueTask InvokeAsync(UiaSelector selector, CancellationToken cancellationToken);

    ValueTask SetValueAsync(UiaSelector selector, string value, CancellationToken cancellationToken);

    ValueTask SelectAsync(UiaSelector selector, CancellationToken cancellationToken);

    ValueTask<UiaElement> WaitAsync(UiaSelector selector, TimeSpan timeout, CancellationToken cancellationToken);

    IAsyncEnumerable<UiaEvent> WatchAsync(
        UiaSelector? scope,
        IReadOnlyCollection<string> eventTypes,
        CancellationToken cancellationToken);
}
