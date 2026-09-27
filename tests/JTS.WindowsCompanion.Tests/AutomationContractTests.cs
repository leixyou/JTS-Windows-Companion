using JTS.WindowsCompanion.Automation;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Windows.Automation;

namespace JTS.WindowsCompanion.Tests;

public sealed class AutomationContractTests
{
    [Fact]
    public void Selector_RequiresAtLeastOneStableField()
    {
        Assert.Throws<ArgumentException>(() => new UiaSelector().Validate());
        new UiaSelector(AutomationId: "save-button").Validate();
        new UiaSelector(Name: "Save", ControlType: "Button", ProcessId: 123).Validate();
    }

    [Fact]
    public void Selector_RejectsInvalidProcessId()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new UiaSelector(ProcessId: 0).Validate());
    }

    [Fact]
    public void MutationSelector_RequiresProcessScopeAndStableIdentity()
    {
        Assert.Throws<ArgumentException>(
            () => new UiaSelector(AutomationId: "save-button").ValidateForMutation());
        Assert.Throws<ArgumentException>(
            () => new UiaSelector(ControlType: "Button", ProcessId: 123).ValidateForMutation());

        new UiaSelector(AutomationId: "save-button", ProcessId: 123).ValidateForMutation();
        new UiaSelector(Name: "Save", ControlType: "Button", ProcessId: 123)
            .ValidateForMutation();
    }

    [Fact]
    public void MutationExecutor_StopsWhenCancellationArrivesDuringUniqueLookup()
    {
        using var cancellation = new CancellationTokenSource();
        var patternResolved = false;
        var mutated = false;

        Assert.Throws<OperationCanceledException>(() =>
            UiAutomationMutationExecutor.Execute(
                () =>
                {
                    cancellation.Cancel();
                    return new object();
                },
                _ =>
                {
                    patternResolved = true;
                    return new object();
                },
                (_, _) => mutated = true,
                cancellation.Token));

        Assert.False(patternResolved);
        Assert.False(mutated);
    }

    [Fact]
    public void MutationExecutor_StopsWhenCancellationArrivesDuringPatternResolution()
    {
        using var cancellation = new CancellationTokenSource();
        var mutated = false;

        Assert.Throws<OperationCanceledException>(() =>
            UiAutomationMutationExecutor.Execute(
                () => new object(),
                _ =>
                {
                    cancellation.Cancel();
                    return new object();
                },
                (_, _) => mutated = true,
                cancellation.Token));

        Assert.False(mutated);
    }

    [Fact]
    public void MutationExecutor_StopsWhenCancellationArrivesDuringFinalPreparation()
    {
        using var cancellation = new CancellationTokenSource();
        var mutated = false;

        Assert.Throws<OperationCanceledException>(() =>
            UiAutomationMutationExecutor.Execute(
                () => new object(),
                _ => new object(),
                (_, token) =>
                {
                    cancellation.Cancel();
                    token.ThrowIfCancellationRequested();
                    mutated = true;
                },
                cancellation.Token));

        Assert.False(mutated);
    }

    [Fact]
    public void MutationSelectorAmbiguityUsesNonRetryableProtocolError()
    {
        var elementWasRead = false;

        var failure = Assert.Throws<CompanionProtocolException>(() =>
            UiAutomationMutationExecutor.RequireUnique(
                count: 2,
                _ =>
                {
                    elementWasRead = true;
                    return new object();
                }));

        Assert.Equal("UIA_SELECTOR_AMBIGUOUS", failure.Code);
        Assert.False(elementWasRead);
    }
}
