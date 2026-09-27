namespace JTS.WindowsCompanion.Windows.Managed;

public enum ManagedServiceStartupMode
{
    Service,
    DebugConsole,
}

public static class ManagedServiceStartupArguments
{
    public static ManagedServiceStartupMode Parse(
        IReadOnlyList<string> arguments,
        bool debugConsoleHostEnabled)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        if (arguments.Count == 0)
        {
            return ManagedServiceStartupMode.Service;
        }

        if (debugConsoleHostEnabled
            && arguments.Count == 1
            && string.Equals(arguments[0], "--console", StringComparison.Ordinal))
        {
            return ManagedServiceStartupMode.DebugConsole;
        }

        throw new ArgumentException("The managed service startup request is invalid.", nameof(arguments));
    }
}
