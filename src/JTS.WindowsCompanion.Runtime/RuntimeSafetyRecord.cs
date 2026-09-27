using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace JTS.WindowsCompanion.Runtime;

internal enum RuntimeSafetyState : byte { Clean, Dispatching, Quarantined }

internal sealed record RuntimeSafetyRecord(Guid StoreId, RuntimeSafetyState State, Guid IncidentId,
    Guid? RequestId, string Reason, long ChangedAt)
{
    internal static RuntimeSafetyRecord Clean(Guid id, long now) => new(id, RuntimeSafetyState.Clean, Guid.Empty, null, "OK", now);
}

// Fixed-size, versioned local record. This is not an endpoint wire protocol.
internal static class RuntimeSafetyCodec
{
    internal const int MaximumCiphertext = 8192;
    private const int RecordSize = 59;
    private static readonly string[] Reasons = ["OK", "EXECUTION_IN_FLIGHT", "EXECUTOR_STATE_UNKNOWN",
        "RUNTIME_RESTART_INTERRUPTED", "LEGACY_STORE_REVIEW_REQUIRED", "EXECUTOR_DID_NOT_STOP"];
    internal static JobRuntimeException Invalid() => new("JOB_SAFETY_AUTHENTICATION_FAILED");
    private static byte[] Purpose(Guid storeId) => Encoding.UTF8.GetBytes($"JTS-JOB-SAFETY-V1/record\n{storeId:D}");

    internal static byte[] Seal(RuntimeSafetyRecord record, ITaskPayloadProtector protector)
    {
        Validate(record);
        var clear = new byte[RecordSize];
        try
        {
            clear[0] = 1;
            record.StoreId.TryWriteBytes(clear.AsSpan(1, 16));
            clear[17] = (byte)record.State;
            record.IncidentId.TryWriteBytes(clear.AsSpan(18, 16));
            (record.RequestId ?? Guid.Empty).TryWriteBytes(clear.AsSpan(34, 16));
            clear[50] = checked((byte)Array.IndexOf(Reasons, record.Reason));
            BinaryPrimitives.WriteInt64LittleEndian(clear.AsSpan(51), record.ChangedAt);
            var cipher = protector.Protect(clear, Purpose(record.StoreId));
            if (cipher is not { Length: > 0 and <= MaximumCiphertext }) throw Invalid();
            return cipher;
        }
        finally { CryptographicOperations.ZeroMemory(clear); }
    }

    internal static RuntimeSafetyRecord Open(byte[] cipher, Guid storeId, ITaskPayloadProtector protector)
    {
        if (cipher.Length is < 1 or > MaximumCiphertext) throw Invalid();
        byte[]? clear = null;
        try
        {
            clear = protector.Unprotect(cipher, Purpose(storeId));
            if (clear is not { Length: RecordSize } || clear[0] != 1 || clear[50] >= Reasons.Length) throw Invalid();
            var requestId = new Guid(clear.AsSpan(34, 16));
            var record = new RuntimeSafetyRecord(new Guid(clear.AsSpan(1, 16)), (RuntimeSafetyState)clear[17],
                new Guid(clear.AsSpan(18, 16)), requestId == Guid.Empty ? null : requestId,
                Reasons[clear[50]], BinaryPrimitives.ReadInt64LittleEndian(clear.AsSpan(51)));
            if (record.StoreId != storeId) throw Invalid();
            Validate(record);
            return record;
        }
        catch (CryptographicException) { throw Invalid(); }
        finally { if (clear is not null) CryptographicOperations.ZeroMemory(clear); }
    }

    private static void Validate(RuntimeSafetyRecord record)
    {
        if (record.StoreId == Guid.Empty || record.RequestId == Guid.Empty
            || record.ChangedAt is < -62135596800000 or > 253402300799999) throw Invalid();
        var valid = record.State switch
        {
            RuntimeSafetyState.Clean => record.IncidentId == Guid.Empty && record.RequestId is null && record.Reason == "OK",
            RuntimeSafetyState.Dispatching => record.IncidentId != Guid.Empty && record.RequestId is not null && record.Reason == "EXECUTION_IN_FLIGHT",
            RuntimeSafetyState.Quarantined => record.IncidentId != Guid.Empty && record.Reason is
                "EXECUTOR_STATE_UNKNOWN" or "RUNTIME_RESTART_INTERRUPTED" or "LEGACY_STORE_REVIEW_REQUIRED" or "EXECUTOR_DID_NOT_STOP",
            _ => false,
        };
        if (!valid) throw Invalid();
    }
}
