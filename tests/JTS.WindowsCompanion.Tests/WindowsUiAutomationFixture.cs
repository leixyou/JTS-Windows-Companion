using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using JTS.WindowsCompanion.Windows.Elevation;

namespace JTS.WindowsCompanion.Tests;

[SupportedOSPlatform("windows10.0")]
internal sealed class WindowsUiAutomationFixture : IAsyncDisposable
{
    public const string ExecutableEnvironmentVariable =
        "JTS_UIA_FIXTURE_EXECUTABLE";

    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web);
    private readonly NamedPipeServerStream _pipe;
    private readonly Process _process;
    private readonly StreamReader _reader;
    private readonly StreamWriter _writer;
    private int _disposed;

    private WindowsUiAutomationFixture(
        NamedPipeServerStream pipe,
        Process process,
        StreamReader reader,
        StreamWriter writer,
        FixtureResponse hello)
    {
        _pipe = pipe;
        _process = process;
        _reader = reader;
        _writer = writer;
        ProcessId = hello.ProcessId
            ?? throw new InvalidDataException("The UI Automation fixture PID is missing.");
        WindowName = Required(hello.WindowName, "window name");
        EditorName = Required(hello.EditorName, "editor name");
        ButtonName = Required(hello.ButtonName, "button name");
    }

    public int ProcessId { get; }

    public string WindowName { get; }

    public string EditorName { get; }

    public string ButtonName { get; }

    public static async ValueTask<WindowsUiAutomationFixture> StartAsync(
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10))
        {
            throw new PlatformNotSupportedException(
                "The UI Automation fixture requires Windows 10 or Windows 11.");
        }

        var executable = ResolveExecutable();
        var pipeName = $"JTS.Terminal.UIA.Fixture.{Guid.NewGuid():N}";
        var pipe = new NamedPipeServerStream(
            pipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
            4_096,
            4_096);
        Process? process = null;
        StreamReader? reader = null;
        StreamWriter? writer = null;
        var handedOff = false;
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = executable,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            startInfo.ArgumentList.Add("--pipe");
            startInfo.ArgumentList.Add(pipeName);
            process = Process.Start(startInfo)
                ?? throw new InvalidOperationException(
                    "Windows did not start the UI Automation fixture process.");
            using var connectionTimeout = new CancellationTokenSource(
                TimeSpan.FromSeconds(15));
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                connectionTimeout.Token);
            await pipe.WaitForConnectionAsync(linked.Token).ConfigureAwait(false);
            var peerProcessId = NamedPipePeerProcess.GetClientProcessId(pipe);
            if (peerProcessId != process.Id)
            {
                throw new UnauthorizedAccessException(
                    "The UI Automation fixture pipe peer is not the launched child process.");
            }

            reader = new StreamReader(
                pipe,
                new UTF8Encoding(false, true),
                detectEncodingFromByteOrderMarks: false,
                bufferSize: 4_096,
                leaveOpen: true);
            writer = new StreamWriter(
                pipe,
                new UTF8Encoding(false, true),
                bufferSize: 4_096,
                leaveOpen: true)
            {
                AutoFlush = true,
            };
            var hello = await ReadResponseAsync(reader, linked.Token).ConfigureAwait(false);
            if (!hello.Ok
                || hello.SchemaVersion != 1
                || hello.Error is not null
                || hello.ProcessId != process.Id
                || hello.Value is not null)
            {
                throw new InvalidDataException(
                    "The UI Automation fixture handshake is invalid.");
            }

            var fixture = new WindowsUiAutomationFixture(
                pipe,
                process,
                reader,
                writer,
                hello);
            handedOff = true;
            process = null;
            reader = null;
            writer = null;
            return fixture;
        }
        finally
        {
            if (!handedOff)
            {
                writer?.Dispose();
                reader?.Dispose();
                pipe.Dispose();
                if (process is not null)
                {
                    await StopForCleanupAsync(process).ConfigureAwait(false);
                    process.Dispose();
                }
            }
        }
    }

    public async ValueTask<string> ReadEditorValueAsync(
        CancellationToken cancellationToken)
    {
        var response = await ExchangeAsync("read", cancellationToken).ConfigureAwait(false);
        return response.Value
            ?? throw new InvalidDataException(
                "The UI Automation fixture did not return the editor value.");
    }

    public async ValueTask WaitForInvokeAsync(CancellationToken cancellationToken)
    {
        var response = await ExchangeAsync("waitInvoke", cancellationToken)
            .ConfigureAwait(false);
        if (response.Value is not null)
        {
            throw new InvalidDataException(
                "The UI Automation fixture invocation response is malformed.");
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        Exception? shutdownFailure = null;
        try
        {
            if (!_process.HasExited)
            {
                try
                {
                    _ = await ExchangeCoreAsync("close", CancellationToken.None)
                        .ConfigureAwait(false);
                }
                catch (Exception exception)
                {
                    shutdownFailure = exception;
                }
            }
        }
        finally
        {
            try
            {
                _writer.Dispose();
            }
            catch (Exception exception)
            {
                shutdownFailure ??= exception;
            }
            try
            {
                _reader.Dispose();
            }
            catch (Exception exception)
            {
                shutdownFailure ??= exception;
            }
            try
            {
                _pipe.Dispose();
            }
            catch (Exception exception)
            {
                shutdownFailure ??= exception;
            }
            if (!await WaitForExitAsync(_process, TimeSpan.FromSeconds(5))
                    .ConfigureAwait(false))
            {
                await KillForCleanupAsync(_process).ConfigureAwait(false);
                shutdownFailure ??= new TimeoutException(
                    "The UI Automation fixture child did not exit naturally.");
            }
            else if (_process.ExitCode != 0)
            {
                shutdownFailure ??= new InvalidOperationException(
                    $"The UI Automation fixture child exited with code {_process.ExitCode}.");
            }

            _process.Dispose();
        }

        if (shutdownFailure is not null)
        {
            throw new InvalidOperationException(
                "The UI Automation fixture child did not shut down cleanly.",
                shutdownFailure);
        }
    }

    private async ValueTask<FixtureResponse> ExchangeAsync(
        string command,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        return await ExchangeCoreAsync(command, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<FixtureResponse> ExchangeCoreAsync(
        string command,
        CancellationToken cancellationToken)
    {
        var request = JsonSerializer.Serialize(
            new FixtureRequest(command),
            JsonOptions);
        await _writer.WriteLineAsync(request.AsMemory(), cancellationToken)
            .ConfigureAwait(false);
        var response = await ReadResponseAsync(_reader, cancellationToken)
            .ConfigureAwait(false);
        if (!response.Ok
            || response.SchemaVersion != 1
            || response.Error is not null
            || response.ProcessId is not null
            || response.WindowName is not null
            || response.EditorName is not null
            || response.ButtonName is not null)
        {
            throw new InvalidDataException(
                response.Error ?? "The UI Automation fixture response is invalid.");
        }

        return response;
    }

    private static async ValueTask<FixtureResponse> ReadResponseAsync(
        StreamReader reader,
        CancellationToken cancellationToken)
    {
        var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new EndOfStreamException(
                "The UI Automation fixture child disconnected.");
        if (line.Length is < 1 or > 4_096)
        {
            throw new InvalidDataException(
                "The UI Automation fixture response length is invalid.");
        }

        return JsonSerializer.Deserialize<FixtureResponse>(line, JsonOptions)
            ?? throw new InvalidDataException(
                "The UI Automation fixture response is missing.");
    }

    private static string ResolveExecutable()
    {
        var configured = Environment.GetEnvironmentVariable(
            ExecutableEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(configured))
        {
            throw new InvalidOperationException(
                $"Set {ExecutableEnvironmentVariable} to the independently built UI Automation fixture executable.");
        }

        var path = Path.GetFullPath(configured);
        if (!File.Exists(path)
            || !string.Equals(
                Path.GetFileName(path),
                "JTS.WindowsCompanion.UiAutomationFixture.exe",
                StringComparison.OrdinalIgnoreCase)
            || (File.GetAttributes(path)
                & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw new InvalidOperationException(
                "The configured UI Automation fixture executable is invalid.");
        }

        return path;
    }

    private static string Required(string? value, string description) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 256
            ? value
            : throw new InvalidDataException(
                $"The UI Automation fixture {description} is invalid.");

    private static async Task StopForCleanupAsync(Process process)
    {
        if (process.HasExited
            || await WaitForExitAsync(process, TimeSpan.FromSeconds(2))
                .ConfigureAwait(false))
        {
            return;
        }

        await KillForCleanupAsync(process).ConfigureAwait(false);
    }

    private static async Task KillForCleanupAsync(Process process)
    {
        if (!process.HasExited)
        {
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync().ConfigureAwait(false);
        }
    }

    private static async Task<bool> WaitForExitAsync(
        Process process,
        TimeSpan timeout)
    {
        if (process.HasExited)
        {
            return true;
        }

        using var timeoutSource = new CancellationTokenSource(timeout);
        try
        {
            await process.WaitForExitAsync(timeoutSource.Token).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException) when (timeoutSource.IsCancellationRequested)
        {
            return process.HasExited;
        }
    }

    private sealed record FixtureRequest(string Command);

    private sealed record FixtureResponse(
        bool Ok,
        string? Error,
        string? WindowName,
        string? EditorName,
        string? ButtonName,
        int? ProcessId,
        string? Value,
        int? SchemaVersion);
}
