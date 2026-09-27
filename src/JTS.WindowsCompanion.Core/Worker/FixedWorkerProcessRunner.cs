using System.Diagnostics;
using JTS.WindowsCompanion.Protocol;

namespace JTS.WindowsCompanion.Worker;

public sealed record FixedWorkerProcessRequest(
    string ExecutablePath,
    IReadOnlyList<string> Arguments,
    ReadOnlyMemory<byte> StandardInput,
    TimeSpan Timeout,
    int MaximumStandardOutputBytes,
    int MaximumStandardErrorBytes,
    string? StandardInputFilePath = null,
    string? StandardOutputFilePath = null);

public sealed record FixedWorkerProcessResult(
    int ExitCode,
    ReadOnlyMemory<byte> StandardOutput,
    ReadOnlyMemory<byte> StandardError);

public interface IFixedWorkerProcessRunner
{
    ValueTask<FixedWorkerProcessResult> RunAsync(
        FixedWorkerProcessRequest request,
        CancellationToken cancellationToken);
}

public sealed class FixedWorkerProcessRunner : IFixedWorkerProcessRunner
{
    public async ValueTask<FixedWorkerProcessResult> RunAsync(
        FixedWorkerProcessRequest request,
        CancellationToken cancellationToken)
    {
        if (!request.StandardInput.IsEmpty && request.StandardInputFilePath is not null)
        {
            throw new ArgumentException("Worker stdin must use memory or a file, not both.", nameof(request));
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = request.ExecutablePath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in request.Arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = startInfo };
        if (!process.Start())
        {
            throw new InvalidOperationException("The fixed VRC worker process did not start.");
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(request.Timeout);
        try
        {
            var standardOutput = request.StandardOutputFilePath is null
                ? ReadBoundedAsync(
                    process.StandardOutput.BaseStream,
                    request.MaximumStandardOutputBytes,
                    timeout.Token)
                : ReadBoundedToFileAsync(
                    process.StandardOutput.BaseStream,
                    request.StandardOutputFilePath,
                    request.MaximumStandardOutputBytes,
                    timeout.Token);
            var standardError = ReadBoundedAsync(
                process.StandardError.BaseStream,
                request.MaximumStandardErrorBytes,
                timeout.Token);
            if (!request.StandardInput.IsEmpty)
            {
                await process.StandardInput.BaseStream.WriteAsync(request.StandardInput, timeout.Token).ConfigureAwait(false);
            }
            else if (request.StandardInputFilePath is { } inputPath)
            {
                await using var input = new FileStream(
                    inputPath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    128 * 1024,
                    FileOptions.Asynchronous | FileOptions.SequentialScan);
                await input.CopyToAsync(process.StandardInput.BaseStream, 128 * 1024, timeout.Token).ConfigureAwait(false);
            }

            process.StandardInput.Close();
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            return new FixedWorkerProcessResult(
                process.ExitCode,
                await standardOutput.ConfigureAwait(false),
                await standardError.ConfigureAwait(false));
        }
        catch
        {
            TryKill(process);
            throw;
        }
    }

    private static async Task<ReadOnlyMemory<byte>> ReadBoundedToFileAsync(
        Stream stream,
        string path,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        await using var output = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            128 * 1024,
            FileOptions.Asynchronous | FileOptions.WriteThrough);
        var buffer = new byte[128 * 1024];
        long total = 0;
        while (true)
        {
            var count = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (count == 0)
            {
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                return ReadOnlyMemory<byte>.Empty;
            }

            total = checked(total + count);
            if (total > maximumBytes)
            {
                throw new CompanionProtocolException(
                    "WORKER_OUTPUT_TOO_LARGE",
                    "The fixed VRC worker exceeded its output limit.");
            }

            await output.WriteAsync(buffer.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task<ReadOnlyMemory<byte>> ReadBoundedAsync(
        Stream stream,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        if (maximumBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        }

        using var output = new MemoryStream(Math.Min(maximumBytes, 128 * 1024));
        var buffer = new byte[64 * 1024];
        var exceeded = false;
        while (true)
        {
            var count = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (count == 0)
            {
                if (exceeded)
                {
                    throw new CompanionProtocolException(
                        "WORKER_OUTPUT_TOO_LARGE",
                        "The fixed VRC worker exceeded its output limit.");
                }

                return output.ToArray();
            }

            var remaining = maximumBytes - checked((int)output.Length);
            if (remaining > 0)
            {
                output.Write(buffer, 0, Math.Min(remaining, count));
            }

            exceeded |= count > remaining;
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (InvalidOperationException)
        {
        }
    }
}
