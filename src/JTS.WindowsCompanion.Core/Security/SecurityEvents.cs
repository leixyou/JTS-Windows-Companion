namespace JTS.WindowsCompanion.Security;

public sealed record SecurityEvent(
    DateTimeOffset Timestamp,
    string Category,
    string Action,
    string Outcome,
    string? ErrorCode = null);

public interface ISecurityEventSink
{
    void Record(SecurityEvent securityEvent);
}

public sealed class NullSecurityEventSink : ISecurityEventSink
{
    public static NullSecurityEventSink Instance { get; } = new();

    private NullSecurityEventSink()
    {
    }

    public void Record(SecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
    }
}
