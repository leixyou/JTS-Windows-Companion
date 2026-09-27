using System.Diagnostics;
using System.Runtime.Versioning;
using JTS.WindowsCompanion.Automation;
using JTS.WindowsCompanion.Windows.Automation;
using Xunit.Abstractions;

namespace JTS.WindowsCompanion.Tests;

[Collection(WindowsInteractiveDesktopCollection.Name)]
public sealed class WindowsUiAutomationIntegrationTests(ITestOutputHelper output)
{
    [Fact]
    public async Task WritableTextSelector_FallsBackToNameAndContinuesAfterRejectedCandidates()
    {
        var attemptedSelectors = new List<UiaSelector>();
        var automation = new TestUiAutomationService((selector, _, _) =>
        {
            attemptedSelectors.Add(selector);
            if (string.Equals(selector.AutomationId, "reject", StringComparison.Ordinal))
            {
                throw new ArgumentException("The first stable candidate was rejected.");
            }

            return ValueTask.CompletedTask;
        });
        var candidates = new[]
        {
            TextElement("unstable", automationId: null, name: null),
            TextElement("rejected", automationId: "reject", name: "Rejected"),
            TextElement("name-fallback", automationId: null, name: "Editor"),
        };

        var selector = await SetFirstWritableTextElementAsync(
            automation,
            processId: 123,
            candidates,
            value: "test",
            CancellationToken.None);

        Assert.Equal(2, attemptedSelectors.Count);
        Assert.Equal("reject", attemptedSelectors[0].AutomationId);
        Assert.Null(attemptedSelectors[1].AutomationId);
        Assert.Equal("Editor", attemptedSelectors[1].Name);
        Assert.Equal(attemptedSelectors[1], selector);
    }

    [WindowsInteractiveUiAutomationFact]
    [SupportedOSPlatform("windows10.0")]
    public async Task IndependentFixtureProcess_SupportsSnapshotFindSetValueInvokeAndWait()
    {
        var automation = new WindowsUiAutomationService();
        using var testDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        await using var fixture = await WindowsUiAutomationFixture.StartAsync(
            testDeadline.Token);
        var processId = fixture.ProcessId;
        Assert.NotEqual(Environment.ProcessId, processId);
        output.WriteLine(
            $"Testing UI Automation against child process {processId} and window '{fixture.WindowName}'.");

        var window = await automation.WaitAsync(
            new UiaSelector(
                Name: fixture.WindowName,
                ControlType: "window",
                ProcessId: processId),
            TimeSpan.FromSeconds(15),
            testDeadline.Token);
        Assert.Equal(processId, window.ProcessId);

        var textElements = await automation.FindAsync(
            new UiaSelector(
                Name: fixture.EditorName,
                ControlType: "edit",
                ProcessId: processId),
            maximumResults: 2,
            testDeadline.Token);
        var textElement = Assert.Single(textElements);
        var marker = $"JTS Terminal UIA integration {Guid.NewGuid():N}";
        var writableSelector = await SetFirstWritableTextElementAsync(
            automation,
            processId,
            [textElement],
            marker,
            testDeadline.Token);
        _ = await automation.WaitAsync(
            writableSelector,
            TimeSpan.FromSeconds(10),
            testDeadline.Token);
        Assert.Equal(
            marker,
            await fixture.ReadEditorValueAsync(testDeadline.Token));

        var buttons = await automation.FindAsync(
            new UiaSelector(
                Name: fixture.ButtonName,
                ControlType: "button",
                ProcessId: processId),
            maximumResults: 2,
            testDeadline.Token);
        var button = Assert.Single(buttons);
        await automation.InvokeAsync(
            StableMutationSelector(button, processId),
            testDeadline.Token);
        await fixture.WaitForInvokeAsync(testDeadline.Token);

        var snapshot = await automation.SnapshotAsync(
            maximumDepth: 32,
            maximumNodes: 20_000,
            testDeadline.Token);
        Assert.True(snapshot.NodeCount > 1);
        Assert.True(
            ContainsProcess(snapshot.Root, processId),
            $"The desktop snapshot did not contain the test-owned process {processId}.");
    }

    private static async Task<UiaSelector> SetFirstWritableTextElementAsync(
        IUiAutomationService automation,
        int processId,
        IReadOnlyList<UiaElement> candidates,
        string value,
        CancellationToken cancellationToken)
    {
        var failures = new List<string>();
        foreach (var candidate in candidates)
        {
            var automationId = string.IsNullOrWhiteSpace(candidate.AutomationId)
                ? null
                : candidate.AutomationId;
            var name = automationId is null && !string.IsNullOrWhiteSpace(candidate.Name)
                ? candidate.Name
                : null;
            if (automationId is null && name is null)
            {
                failures.Add(
                    $"{candidate.ControlType}/<no stable automation id or name>: skipped.");
                continue;
            }

            var selector = new UiaSelector(
                AutomationId: automationId,
                Name: name,
                ControlType: candidate.ControlType,
                ProcessId: processId);
            try
            {
                await automation.SetValueAsync(selector, value, cancellationToken);
                return selector;
            }
            catch (Exception exception) when (
                exception is ArgumentException or InvalidOperationException or KeyNotFoundException)
            {
                failures.Add(
                    $"{candidate.ControlType}/{automationId ?? name}: {exception.Message}");
            }
        }

        throw new InvalidOperationException(
            $"The UI Automation target exposed {candidates.Count} text elements, but none supported a writable ValuePattern. "
            + string.Join(" | ", failures));
    }

    private static UiaElement TextElement(
        string runtimeId,
        string? automationId,
        string? name) => new(
            RuntimeId: runtimeId,
            AutomationId: automationId,
            Name: name,
            ControlType: "Edit",
            ProcessId: 123,
            IsEnabled: true,
            IsOffscreen: false,
            Bounds: new UiaBounds(0, 0, 100, 20),
            Children: []);

    private static UiaSelector StableMutationSelector(UiaElement element, int processId)
    {
        var automationId = string.IsNullOrWhiteSpace(element.AutomationId)
            ? null
            : element.AutomationId;
        var name = automationId is null && !string.IsNullOrWhiteSpace(element.Name)
            ? element.Name
            : null;
        Assert.True(
            automationId is not null || name is not null,
            "The test-owned UI control did not expose a stable automation ID or name.");
        return new UiaSelector(
            AutomationId: automationId,
            Name: name,
            ControlType: element.ControlType,
            ProcessId: processId);
    }

    private sealed class TestUiAutomationService(
        Func<UiaSelector, string, CancellationToken, ValueTask> setValue)
        : IUiAutomationService
    {
        public ValueTask<UiaSnapshot> SnapshotAsync(
            int maximumDepth,
            int maximumNodes,
            CancellationToken cancellationToken) => throw Unsupported();

        public ValueTask<IReadOnlyList<UiaElement>> FindAsync(
            UiaSelector selector,
            int maximumResults,
            CancellationToken cancellationToken) => throw Unsupported();

        public ValueTask InvokeAsync(
            UiaSelector selector,
            CancellationToken cancellationToken) => throw Unsupported();

        public ValueTask SetValueAsync(
            UiaSelector selector,
            string value,
            CancellationToken cancellationToken) =>
            setValue(selector, value, cancellationToken);

        public ValueTask SelectAsync(
            UiaSelector selector,
            CancellationToken cancellationToken) => throw Unsupported();

        public ValueTask<UiaElement> WaitAsync(
            UiaSelector selector,
            TimeSpan timeout,
            CancellationToken cancellationToken) => throw Unsupported();

        public IAsyncEnumerable<UiaEvent> WatchAsync(
            UiaSelector? scope,
            IReadOnlyCollection<string> eventTypes,
            CancellationToken cancellationToken) => throw Unsupported();

        private static NotSupportedException Unsupported() => new();
    }

    private static bool ContainsProcess(UiaElement element, int processId) =>
        element.ProcessId == processId
        || element.Children.Any(child => ContainsProcess(child, processId));

}

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class WindowsInteractiveDesktopCollection
{
    public const string Name = "Windows interactive desktop";
}

[AttributeUsage(AttributeTargets.Method)]
public sealed class WindowsInteractiveUiAutomationFactAttribute : FactAttribute
{
    public const string EnvironmentVariable = "JTS_RUN_INTERACTIVE_UIA_TESTS";

    public WindowsInteractiveUiAutomationFactAttribute()
    {
        Skip = GetSkipReason();
    }

    private static string? GetSkipReason()
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10))
        {
            return "Requires Windows 10 or Windows 11.";
        }

        if (!Environment.UserInteractive)
        {
            return "Requires an interactive Windows desktop.";
        }

        using var currentProcess = Process.GetCurrentProcess();
        if (currentProcess.SessionId == 0)
        {
            return "Requires an interactive user session outside Session 0.";
        }

        if (!string.Equals(
                Environment.GetEnvironmentVariable(EnvironmentVariable),
                "1",
                StringComparison.Ordinal))
        {
            return $"Set {EnvironmentVariable}=1 to run the independent-process UI Automation test.";
        }

        return null;
    }
}
