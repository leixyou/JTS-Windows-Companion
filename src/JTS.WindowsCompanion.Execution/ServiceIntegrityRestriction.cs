namespace JTS.WindowsCompanion.Execution;

// Service startup only. Never turns an administrator/elevated/privileged token into an accepted Worker.
internal static class ServiceIntegrityRestriction
{
    internal const int Medium = 8192;
    internal static void Apply(string expectedSid, Func<WorkerTokenFacts> readCurrent, Action lowerCurrentToMedium)
    {
        var before = readCurrent();
        if (before.IntegrityRid is not (Medium or 12288 or 16384))
            throw new InvalidOperationException("SERVICE_INTEGRITY_CLASS_REJECTED");
        // Validate every original fact except the intended integrity reduction BEFORE any native write.
        // In particular TokenElevation, forbidden groups and even disabled dangerous privileges remain rejected.
        WorkerAccountPolicy.Validate(expectedSid, before with { IntegrityRid = Medium });
        if (before.IntegrityRid != Medium) lowerCurrentToMedium();
        var after = readCurrent();
        WorkerAccountPolicy.Validate(expectedSid, after);
        if (after.IntegrityRid != Medium) throw new InvalidOperationException("SERVICE_INTEGRITY_REDUCTION_UNCONFIRMED");
    }
}
