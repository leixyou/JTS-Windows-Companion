namespace JTS.WindowsCompanion.Transport;

/// <summary>A failure of native channel I/O, never protocol or authorization rejection.</summary>
public sealed class CompanionChannelUnavailableException : IOException
{
    public string Operation { get; }
    public int NativeErrorCode { get; }

    public CompanionChannelUnavailableException(string operation, int nativeErrorCode, Exception innerException)
        : base("The RDP Companion channel is temporarily unavailable.", innerException)
    {
        if (operation is not ("open" or "read" or "write")) throw new ArgumentException("Unknown channel operation.", nameof(operation));
        Operation = operation;
        NativeErrorCode = nativeErrorCode;
    }
}
