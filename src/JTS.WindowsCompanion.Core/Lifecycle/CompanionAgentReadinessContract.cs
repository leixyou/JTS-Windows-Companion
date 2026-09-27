namespace JTS.WindowsCompanion.Lifecycle;

public static class CompanionAgentReadinessContract
{
    public const string ArgumentName = "--startup-ready-pipe";
    public const byte ProtocolVersion = 1;

    private const string PipeNamePrefix = "JTS.Terminal.Agent.Ready.";

    public static string CreatePipeName() =>
        PipeNamePrefix + Guid.NewGuid().ToString("N");

    public static bool IsValidPipeName(string? pipeName) =>
        pipeName is not null &&
        pipeName.StartsWith(PipeNamePrefix, StringComparison.Ordinal) &&
        Guid.TryParseExact(pipeName[PipeNamePrefix.Length..], "N", out _);

    public static void ValidatePipeName(string? pipeName)
    {
        if (!IsValidPipeName(pipeName))
        {
            throw new ArgumentException("The Agent startup readiness pipe name is invalid.", nameof(pipeName));
        }
    }
}
