namespace JTS.WindowsCompanion.Runtime;

public sealed record ExecutionRecoveryRequirement(Guid StoreId, Guid IncidentId, Guid? RequestId,
    string Reason, DateTimeOffset RecordedAt);

/// <summary>
/// Trusted local authority only, never a remote grant or Worker self-attestation. Implementations must
/// verify that all possible executor descendants are stopped and remain fenced until this call returns.
/// A pipe disconnect, SCM stopped status, receipt or restarted authority alone is insufficient proof.
/// Implementations must return promptly and honor cancellation. There is no permissive default verifier.
/// </summary>
public interface IJobRecoveryVerifier
{
    ValueTask<bool> VerifyStoppedAsync(ExecutionRecoveryRequirement incident, CancellationToken cancellationToken);
}
