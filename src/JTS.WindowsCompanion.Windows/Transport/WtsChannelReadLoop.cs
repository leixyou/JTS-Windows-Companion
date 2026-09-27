using System.ComponentModel;
using System.IO;

namespace JTS.WindowsCompanion.Windows.Transport;

internal readonly record struct WtsChannelReadResult(bool Succeeded, int BytesRead, int ErrorCode);

/// <summary>Keeps idle WTS reads cancellable without treating pending I/O as data.</summary>
internal static class WtsChannelReadLoop
{
    private static readonly TimeSpan RetryDelay = TimeSpan.FromMilliseconds(25);

    internal static async Task<byte[]> ReadAsync(
        Func<byte[], WtsChannelReadResult> read,
        int bufferSize,
        CancellationToken cancellationToken,
        Func<TimeSpan, CancellationToken, Task>? waitForRetry = null)
    {
        var buffer = new byte[bufferSize];
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = read(buffer);
            cancellationToken.ThrowIfCancellationRequested();
            if (result.Succeeded)
            {
                if (result.BytesRead < 0 || result.BytesRead > buffer.Length)
                {
                    throw new InvalidDataException("The RDP Dynamic Virtual Channel returned an invalid read count.");
                }
                if (result.BytesRead > 0)
                {
                    return buffer.AsSpan(0, result.BytesRead).ToArray();
                }
            }
            else if (result.BytesRead != 0 || result.ErrorCode is not (0 or 121 or 996 or 1460))
            {
                throw new Win32Exception(result.ErrorCode, "Reading from the RDP Dynamic Virtual Channel failed.");
            }

            // Windows returned ERROR_IO_INCOMPLETE (996) for an idle finite
            // timeout in real DVC acceptance. It means no completed read, not
            // a disconnected channel. Preserve the caller's decoder/reassembly
            // state and pace even immediate pending/empty native returns.
            if (waitForRetry is null)
            {
                await Task.Delay(RetryDelay, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await waitForRetry(RetryDelay, cancellationToken).ConfigureAwait(false);
            }
        }
    }
}
