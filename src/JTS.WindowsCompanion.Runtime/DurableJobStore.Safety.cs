namespace JTS.WindowsCompanion.Runtime;

public sealed partial class DurableJobStore
{
    private bool _recoveryInProgress;
    internal static readonly TimeSpan RecoveryTimeout = TimeSpan.FromSeconds(10);

    public ExecutionRecoveryRequirement? GetRecoveryRequirement()
    {
        lock (_gate)
        {
            Check(); var safety = ReadSafety();
            return safety.State == RuntimeSafetyState.Quarantined ? RecoveryRequirement(safety) : null;
        }
    }

    /// <summary>Offline local recovery only. Never invoke this from a network or MCP request.</summary>
    public async ValueTask ConfirmExecutionRecoveryAsync(Guid incidentId, IJobRecoveryVerifier verifier,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        RuntimeSafetyRecord expected;
        lock (_gate)
        {
            Check();
            if (_runtimeAttached) throw new JobRuntimeException("JOB_RUNTIME_STILL_ATTACHED");
            if (_recoveryInProgress) throw new JobRuntimeException("JOB_RECOVERY_IN_PROGRESS");
            expected = ReadSafety();
            if (expected.State != RuntimeSafetyState.Quarantined || expected.IncidentId != incidentId)
                throw new JobRuntimeException("JOB_RECOVERY_INCIDENT_MISMATCH");
            cancellationToken.ThrowIfCancellationRequested();
            _recoveryInProgress = true;
        }
        using var deadline = new CancellationTokenSource(RecoveryTimeout, _clock);
        using var combined = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        try
        {
            var verified = await verifier.VerifyStoppedAsync(RecoveryRequirement(expected), combined.Token)
                .AsTask().WaitAsync(combined.Token).ConfigureAwait(false);
            lock (_gate)
            {
                Check(); combined.Token.ThrowIfCancellationRequested();
                if (!verified) throw new JobRuntimeException("JOB_RECOVERY_NOT_CONFIRMED");
                if (ReadSafety() != expected) throw new JobRuntimeException("JOB_RECOVERY_INCIDENT_MISMATCH");
                using var transaction = _db.BeginTransaction();
                WriteSafety(RuntimeSafetyRecord.Clean(_storeId, NowMilliseconds()), transaction);
                transaction.Commit();
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && deadline.IsCancellationRequested)
        { throw new JobRuntimeException("JOB_RECOVERY_TIMED_OUT"); }
        finally { lock (_gate) _recoveryInProgress = false; }
    }

    internal void QuarantineExecution(Guid requestId, string reason)
    {
        if (reason is not ("EXECUTOR_STATE_UNKNOWN" or "EXECUTOR_DID_NOT_STOP")) throw new ArgumentException("Invalid quarantine reason.");
        lock (_gate)
        {
            Check(); var safety = ReadSafety();
            if (safety.State != RuntimeSafetyState.Quarantined)
                safety = new(_storeId, RuntimeSafetyState.Quarantined,
                    safety.IncidentId == Guid.Empty ? Guid.NewGuid() : safety.IncidentId, requestId, reason, NowMilliseconds());
            using var transaction = _db.BeginTransaction();
            WriteSafety(safety, transaction);
            using var command = Command("""
                UPDATE jobs SET state=7,completed_ms=$now,result_code=$reason,payload=NULL WHERE state IN (1,2);
                UPDATE jobs SET state=5,completed_ms=$now,result_code='EXECUTOR_STATE_UNKNOWN',payload=NULL WHERE state=0;
                """, ("$now", NowMilliseconds()), ("$reason", reason));
            command.Transaction = transaction; command.ExecuteNonQuery(); transaction.Commit();
        }
    }

    private static ExecutionRecoveryRequirement RecoveryRequirement(RuntimeSafetyRecord safety)
        => new(safety.StoreId, safety.IncidentId, safety.RequestId, safety.Reason, DateTimeOffset.FromUnixTimeMilliseconds(safety.ChangedAt));
}
