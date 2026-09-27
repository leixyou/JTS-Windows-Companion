#if WINDOWS_UIA
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using System.Windows.Automation;
using JTS.WindowsCompanion.Automation;
using UiaAutomation = System.Windows.Automation.Automation;

namespace JTS.WindowsCompanion.Windows.Automation;

public sealed class WindowsUiAutomationService : IUiAutomationService
{
    public ValueTask<UiaSnapshot> SnapshotAsync(
        int maximumDepth,
        int maximumNodes,
        CancellationToken cancellationToken)
    {
        EnsureWindows();
        ValidateLimits(maximumDepth, maximumNodes);
        return new ValueTask<UiaSnapshot>(Task.Run(
            () => BuildSnapshot(maximumDepth, maximumNodes, cancellationToken),
            cancellationToken));
    }

    public ValueTask<IReadOnlyList<UiaElement>> FindAsync(
        UiaSelector selector,
        int maximumResults,
        CancellationToken cancellationToken)
    {
        EnsureWindows();
        ArgumentNullException.ThrowIfNull(selector);
        selector.Validate();
        if (maximumResults is < 1 or > 500)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumResults));
        }

        return new ValueTask<IReadOnlyList<UiaElement>>(Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            var matches = AutomationElement.RootElement.FindAll(TreeScope.Descendants, BuildCondition(selector));
            var result = new List<UiaElement>(Math.Min(matches.Count, maximumResults));
            for (var index = 0; index < matches.Count && result.Count < maximumResults; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                result.Add(ToElement(matches[index], []));
            }

            return (IReadOnlyList<UiaElement>)result;
        }, cancellationToken));
    }

    public ValueTask InvokeAsync(UiaSelector selector, CancellationToken cancellationToken) =>
        RunPatternAsync<InvokePattern>(
            selector,
            InvokePattern.Pattern,
            (pattern, _) => pattern.Invoke(),
            cancellationToken);

    public ValueTask SetValueAsync(UiaSelector selector, string value, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(value);
        return RunPatternAsync<ValuePattern>(selector, ValuePattern.Pattern, (pattern, token) =>
        {
            var isReadOnly = pattern.Current.IsReadOnly;
            token.ThrowIfCancellationRequested();
            if (isReadOnly)
            {
                throw new InvalidOperationException("The selected UI Automation value is read-only.");
            }

            pattern.SetValue(value);
        }, cancellationToken);
    }

    public ValueTask SelectAsync(UiaSelector selector, CancellationToken cancellationToken) =>
        RunPatternAsync<SelectionItemPattern>(
            selector,
            SelectionItemPattern.Pattern,
            (pattern, _) => pattern.Select(),
            cancellationToken);

    public async ValueTask<UiaElement> WaitAsync(
        UiaSelector selector,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        EnsureWindows();
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        using var timeoutSource = new CancellationTokenSource(timeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutSource.Token);
        while (true)
        {
            var matches = await FindAsync(selector, 1, linked.Token).ConfigureAwait(false);
            if (matches.Count > 0)
            {
                return matches[0];
            }

            try
            {
                await Task.Delay(100, linked.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (timeoutSource.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException("The UI Automation selector did not appear before the deadline.");
            }
        }
    }

    public async IAsyncEnumerable<UiaEvent> WatchAsync(
        UiaSelector? scope,
        IReadOnlyCollection<string> eventTypes,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        EnsureWindows();
        if (eventTypes.Count is < 1 or > 8)
        {
            throw new ArgumentOutOfRangeException(nameof(eventTypes));
        }

        scope?.Validate();
        var scopeElement = scope is null ? AutomationElement.RootElement : FindOne(scope);
        var channel = Channel.CreateBounded<UiaEvent>(new BoundedChannelOptions(128)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.DropOldest,
        });
        var subscriptions = new List<(AutomationEvent Event, AutomationEventHandler Handler)>();
        try
        {
            foreach (var eventType in eventTypes.Distinct(StringComparer.Ordinal))
            {
                var automationEvent = ResolveEvent(eventType);
                AutomationEventHandler handler = (sender, raisedEvent) =>
                {
                    if (sender is not AutomationElement element)
                    {
                        return;
                    }

                    try
                    {
                        var converted = ToElement(element, []);
                        channel.Writer.TryWrite(new UiaEvent(
                            raisedEvent.EventId.ProgrammaticName,
                            converted.RuntimeId,
                            converted.AutomationId,
                            converted.Name,
                            DateTimeOffset.UtcNow));
                    }
                    catch (ElementNotAvailableException)
                    {
                    }
                };
                UiaAutomation.AddAutomationEventHandler(automationEvent, scopeElement, TreeScope.Subtree, handler);
                subscriptions.Add((automationEvent, handler));
            }

            await foreach (var item in channel.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                yield return item;
            }
        }
        finally
        {
            foreach (var subscription in subscriptions)
            {
                UiaAutomation.RemoveAutomationEventHandler(subscription.Event, scopeElement, subscription.Handler);
            }

            channel.Writer.TryComplete();
        }
    }

    private static UiaSnapshot BuildSnapshot(int maximumDepth, int maximumNodes, CancellationToken cancellationToken)
    {
        var count = 0;
        var truncated = false;
        UiaElement Visit(AutomationElement element, int depth)
        {
            cancellationToken.ThrowIfCancellationRequested();
            count++;
            var children = new List<UiaElement>();
            if (depth < maximumDepth && count < maximumNodes)
            {
                var child = TreeWalker.ControlViewWalker.GetFirstChild(element);
                while (child is not null && count < maximumNodes)
                {
                    try
                    {
                        children.Add(Visit(child, depth + 1));
                        child = TreeWalker.ControlViewWalker.GetNextSibling(child);
                    }
                    catch (ElementNotAvailableException)
                    {
                        child = null;
                    }
                }

                truncated |= child is not null;
            }
            else
            {
                truncated = true;
            }

            return ToElement(element, children);
        }

        return new UiaSnapshot(Visit(AutomationElement.RootElement, 0), truncated, count);
    }

    private static ValueTask RunPatternAsync<TPattern>(
        UiaSelector selector,
        AutomationPattern pattern,
        Action<TPattern, CancellationToken> action,
        CancellationToken cancellationToken)
        where TPattern : class
    {
        EnsureWindows();
        ArgumentNullException.ThrowIfNull(selector);
        selector.ValidateForMutation();
        return new ValueTask(Task.Run(() =>
        {
            UiAutomationMutationExecutor.Execute(
                () => FindOneUnique(selector),
                element =>
                    element.TryGetCurrentPattern(pattern, out var patternObject)
                    && patternObject is TPattern typedPattern
                        ? typedPattern
                        : null,
                action,
                cancellationToken);
        }, cancellationToken));
    }

    private static AutomationElement FindOne(UiaSelector selector) =>
        AutomationElement.RootElement.FindFirst(TreeScope.Descendants, BuildCondition(selector))
        ?? throw new KeyNotFoundException("The UI Automation element was not found.");

    private static AutomationElement FindOneUnique(UiaSelector selector)
    {
        var matches = AutomationElement.RootElement.FindAll(
            TreeScope.Descendants,
            BuildCondition(selector));
        return UiAutomationMutationExecutor.RequireUnique(
            matches.Count,
            index => matches[index]);
    }

    private static Condition BuildCondition(UiaSelector selector)
    {
        var conditions = new List<Condition>();
        if (!string.IsNullOrWhiteSpace(selector.AutomationId))
        {
            conditions.Add(new PropertyCondition(AutomationElement.AutomationIdProperty, selector.AutomationId));
        }

        if (!string.IsNullOrWhiteSpace(selector.Name))
        {
            conditions.Add(new PropertyCondition(AutomationElement.NameProperty, selector.Name));
        }

        if (selector.ProcessId is { } processId)
        {
            conditions.Add(new PropertyCondition(AutomationElement.ProcessIdProperty, processId));
        }

        if (!string.IsNullOrWhiteSpace(selector.ControlType))
        {
            conditions.Add(new PropertyCondition(AutomationElement.ControlTypeProperty, ResolveControlType(selector.ControlType)));
        }

        return conditions.Count == 1 ? conditions[0] : new AndCondition(conditions.ToArray());
    }

    private static ControlType ResolveControlType(string value) => value.ToLowerInvariant() switch
    {
        "button" => ControlType.Button,
        "calendar" => ControlType.Calendar,
        "checkbox" => ControlType.CheckBox,
        "combobox" => ControlType.ComboBox,
        "custom" => ControlType.Custom,
        "dataitem" => ControlType.DataItem,
        "document" => ControlType.Document,
        "edit" => ControlType.Edit,
        "group" => ControlType.Group,
        "hyperlink" => ControlType.Hyperlink,
        "image" => ControlType.Image,
        "list" => ControlType.List,
        "listitem" => ControlType.ListItem,
        "menu" => ControlType.Menu,
        "menuitem" => ControlType.MenuItem,
        "pane" => ControlType.Pane,
        "progressbar" => ControlType.ProgressBar,
        "radiobutton" => ControlType.RadioButton,
        "scrollbar" => ControlType.ScrollBar,
        "slider" => ControlType.Slider,
        "spinner" => ControlType.Spinner,
        "splitbutton" => ControlType.SplitButton,
        "statusbar" => ControlType.StatusBar,
        "tab" => ControlType.Tab,
        "tabitem" => ControlType.TabItem,
        "table" => ControlType.Table,
        "text" => ControlType.Text,
        "thumb" => ControlType.Thumb,
        "titlebar" => ControlType.TitleBar,
        "toolbar" => ControlType.ToolBar,
        "tree" => ControlType.Tree,
        "treeitem" => ControlType.TreeItem,
        "window" => ControlType.Window,
        _ => throw new ArgumentException("The UI Automation control type is not supported.", nameof(value)),
    };

    private static AutomationEvent ResolveEvent(string eventType) => eventType switch
    {
        "invoke" => InvokePattern.InvokedEvent,
        "selection" => SelectionItemPattern.ElementSelectedEvent,
        "windowOpened" => WindowPattern.WindowOpenedEvent,
        _ => throw new ArgumentException("The UI Automation event type is not supported.", nameof(eventType)),
    };

    private static UiaElement ToElement(AutomationElement element, IReadOnlyList<UiaElement> children)
    {
        var current = element.Current;
        var bounds = current.BoundingRectangle;
        return new UiaElement(
            string.Join(".", element.GetRuntimeId()),
            EmptyToNull(current.AutomationId),
            EmptyToNull(current.Name),
            current.ControlType.ProgrammaticName.Replace("ControlType.", string.Empty, StringComparison.Ordinal),
            current.ProcessId,
            current.IsEnabled,
            current.IsOffscreen,
            UiAutomationBounds.FromProvider(bounds.X, bounds.Y, bounds.Width, bounds.Height),
            children);
    }

    private static string? EmptyToNull(string value) => string.IsNullOrEmpty(value) ? null : value;

    private static void ValidateLimits(int maximumDepth, int maximumNodes)
    {
        if (maximumDepth is < 1 or > 32 || maximumNodes is < 1 or > 20_000)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumNodes));
        }
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("UI Automation is available only on Windows.");
        }
    }
}
#else
using JTS.WindowsCompanion.Automation;

namespace JTS.WindowsCompanion.Windows.Automation;

public sealed class WindowsUiAutomationService : IUiAutomationService
{
    public ValueTask<UiaSnapshot> SnapshotAsync(int maximumDepth, int maximumNodes, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask<IReadOnlyList<UiaElement>> FindAsync(
        UiaSelector selector,
        int maximumResults,
        CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask InvokeAsync(UiaSelector selector, CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask SetValueAsync(UiaSelector selector, string value, CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask SelectAsync(UiaSelector selector, CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask<UiaElement> WaitAsync(
        UiaSelector selector,
        TimeSpan timeout,
        CancellationToken cancellationToken) => throw Unsupported();

    public IAsyncEnumerable<UiaEvent> WatchAsync(
        UiaSelector? scope,
        IReadOnlyCollection<string> eventTypes,
        CancellationToken cancellationToken) => throw Unsupported();

    private static PlatformNotSupportedException Unsupported() => new(
        "The production UI Automation adapter must be built on Windows with UIAutomationClient available.");
}
#endif
