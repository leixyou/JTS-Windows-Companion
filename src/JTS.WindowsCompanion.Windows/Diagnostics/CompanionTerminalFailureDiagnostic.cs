using System.ComponentModel;
using System.Globalization;
using JTS.WindowsCompanion.Protocol;

namespace JTS.WindowsCompanion.Windows.Diagnostics;

/// <summary>Bounded terminal failure metadata; never formats exception text or payloads.</summary>
public static class CompanionTerminalFailureDiagnostic
{
    public static string Describe(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        var hresult = unchecked((uint)exception.HResult).ToString("X8", CultureInfo.InvariantCulture);
        return exception switch
        {
            Win32Exception native => "type=Win32Exception nativeErrorCode="
                + native.NativeErrorCode.ToString(CultureInfo.InvariantCulture) + " hresult=0x" + hresult,
            CompanionProtocolException protocol => "type=CompanionProtocolException protocolCode="
                + AllowedProtocolCode(protocol.Code) + " hresult=0x" + hresult,
            _ => "type=Exception hresult=0x" + hresult,
        };
    }

    private static string AllowedProtocolCode(string code) => code switch
    {
        "DVC_PDU_HEADER_TRUNCATED" or "DVC_PDU_FLAGS_INVALID" or
        "DVC_PDU_LENGTH_INVALID" or "DVC_PDU_BUFFER_LIMIT" or "DVC_PDU_SEQUENCE_INVALID" or
        "FRAME_TRUNCATED" or "FRAME_MAGIC_INVALID" or "FRAME_TYPE_INVALID" or
        "FRAME_LENGTH_INVALID" or "FRAME_DIGEST_INVALID" or "FRAME_TOO_LARGE" or "FRAME_BUFFER_LIMIT" or
        "FRAME_AUTH_CONTEXT_INVALID" or "FRAME_AUTH_INVALID" or
        "PROTOCOL_VERSION_UNSUPPORTED" or "JSON_INVALID" or "PAIRING_REQUIRED" or
        "BINARY_HANDLER_REQUIRED" or "CHUNK_INVALID" or "CHUNK_TRUNCATED" or
        "CHUNK_LENGTH_INVALID" or "CHUNK_DIGEST_INVALID" => code,
        _ => "UNCLASSIFIED",
    };
}
