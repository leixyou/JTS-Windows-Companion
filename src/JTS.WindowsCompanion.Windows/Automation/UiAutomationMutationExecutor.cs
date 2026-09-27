using JTS.WindowsCompanion.Protocol;

namespace JTS.WindowsCompanion.Windows.Automation;

internal static class UiAutomationMutationExecutor
{
    public static void Execute<TElement, TPattern>(
        Func<TElement> findOneUnique,
        Func<TElement, TPattern?> resolvePattern,
        Action<TPattern, CancellationToken> mutate,
        CancellationToken cancellationToken)
        where TPattern : class
    {
        ArgumentNullException.ThrowIfNull(findOneUnique);
        ArgumentNullException.ThrowIfNull(resolvePattern);
        ArgumentNullException.ThrowIfNull(mutate);

        cancellationToken.ThrowIfCancellationRequested();
        var element = findOneUnique();
        cancellationToken.ThrowIfCancellationRequested();

        var pattern = resolvePattern(element)
            ?? throw new InvalidOperationException(
                "The selected UI Automation element does not support the requested pattern.");
        cancellationToken.ThrowIfCancellationRequested();
        mutate(pattern, cancellationToken);
    }

    public static TElement RequireUnique<TElement>(
        int count,
        Func<int, TElement> elementAt)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        ArgumentNullException.ThrowIfNull(elementAt);
        return count switch
        {
            0 => throw new KeyNotFoundException(
                "The UI Automation element was not found."),
            1 => elementAt(0),
            _ => throw new CompanionProtocolException(
                "UIA_SELECTOR_AMBIGUOUS",
                "The UI Automation mutation selector matched more than one element."),
        };
    }
}
