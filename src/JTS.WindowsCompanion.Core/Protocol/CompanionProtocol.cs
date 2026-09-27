namespace JTS.WindowsCompanion.Protocol;

public static class CompanionProtocol
{
    public const ushort CurrentVersion = 1;
    public const string DynamicVirtualChannelName = "JTS.Companion.v1";
    public const int HeaderLength = 24;
    public const int MaxControlPayloadBytes = 1024 * 1024;
    public const int MaxBinaryPayloadBytes = 8 * 1024 * 1024;
    public const int FrameAuthenticationEnvelopeBytes = 4 + 64;
    public const int MaxAuthenticatedControlPayloadBytes = MaxControlPayloadBytes - FrameAuthenticationEnvelopeBytes;
    public const int MaxAuthenticatedBinaryPayloadBytes = MaxBinaryPayloadBytes - FrameAuthenticationEnvelopeBytes;
    public const int MaxBufferedBytes = MaxBinaryPayloadBytes + HeaderLength;
}

public enum CompanionFrameType : byte
{
    ControlJson = 1,
    BinaryChunk = 2,
    Ping = 3,
    Pong = 4,
}

[Flags]
public enum CompanionFrameFlags : byte
{
    None = 0,
    Final = 1,
    Error = 2,
    Authenticated = 1 << 7,
}

public sealed class CompanionProtocolException : Exception
{
    public CompanionProtocolException(string code, string message)
        : base(message)
    {
        Code = code;
    }

    public string Code { get; }
}
