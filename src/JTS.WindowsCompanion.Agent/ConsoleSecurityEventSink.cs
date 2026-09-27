using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.Agent;

internal sealed class ConsoleSecurityEventSink : ISecurityEventSink
{
    public void Record(SecurityEvent securityEvent)
    {
        // Deliberately excludes payloads, paths, scripts, typed values, credentials, and process output.
        Console.Error.WriteLine(
            "{0:O} category={1} action={2} outcome={3} code={4}",
            securityEvent.Timestamp,
            securityEvent.Category,
            securityEvent.Action,
            securityEvent.Outcome,
            securityEvent.ErrorCode ?? "none");
    }
}
