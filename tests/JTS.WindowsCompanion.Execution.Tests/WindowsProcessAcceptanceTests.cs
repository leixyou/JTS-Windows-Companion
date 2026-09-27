using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using Xunit;

namespace JTS.WindowsCompanion.Execution.Tests;

// These execute real scripts only on an explicitly selected, provisioned standard-account Windows test host.
public sealed class WindowsProcessAcceptanceTests
{
    [WindowsWorkerFact]
    public async Task RealPowerShellPreservesUnicodeAndNonzeroExit()
    {
        using var folder = new TestFolder();
        var executor = new StandardAccountPowerShellExecutor(Environment.GetEnvironmentVariable("JTS_EXECUTION_TEST_WORKER_SID")!);
        var job = ExecutionContractTests.Job("[Console]::Out.Write('中文 😀'); [Console]::Error.Write('错误 stderr 🚀'); exit 7", folder.Path);
        var sink = new ExecutorLifecycleTests.CaptureSink(); using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var result = await executor.ExecuteAsync(job.Binding, job.Payload, sink, timeout.Token);
        Assert.False(result.Success); Assert.Equal("POWERSHELL_EXIT_NONZERO", result.ResultCode);
        var output = Encoding.UTF8.GetString(sink.Bytes.ToArray()); Assert.Contains("中文 😀", output); Assert.Contains("错误 stderr 🚀", output);
        var success = ExecutionContractTests.Job("Write-Output 'done'; exit 0", folder.Path);
        var successSink = new ExecutorLifecycleTests.CaptureSink();
        Assert.True((await executor.ExecuteAsync(success.Binding, success.Payload, successSink, timeout.Token)).Success);
        Assert.Contains("done", Encoding.UTF8.GetString(successSink.Bytes.ToArray()));
    }
    [WindowsWorkerFact]
    public async Task CancellationKillsOrdinaryChildBeforeTerminalReceipt()
    {
        using var folder = new TestFolder();
        var executor = new StandardAccountPowerShellExecutor(Environment.GetEnvironmentVariable("JTS_EXECUTION_TEST_WORKER_SID")!);
        var job = ExecutionContractTests.Job("""
            $p = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList '-NoProfile -NonInteractive -Command Start-Sleep -Seconds 60' -PassThru
            [Console]::Out.WriteLine(('CHILD:' + $p.Id))
            Start-Sleep -Seconds 60
            """, folder.Path);
        var sink = new ChildPidSink(); using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var run = executor.ExecuteAsync(job.Binding, job.Payload, sink, cancel.Token).AsTask();
        try
        {
            var pid = await sink.Pid.Task.WaitAsync(TimeSpan.FromSeconds(10));
            using var child = Process.GetProcessById(pid);
            cancel.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.WaitAsync(TimeSpan.FromSeconds(5)));
            Assert.True(child.HasExited);
        }
        finally
        {
            cancel.Cancel();
            try { await run.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (OperationCanceledException) { }
        }
    }
    private sealed class ChildPidSink : JTS.WindowsCompanion.Runtime.IJobOutputSink
    {
        internal TaskCompletionSource<int> Pid { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly StringBuilder _text = new();
        public ValueTask AppendAsync(ReadOnlyMemory<byte> output, CancellationToken cancellationToken)
        {
            _text.Append(Encoding.UTF8.GetString(output.Span));
            var match = Regex.Match(_text.ToString(), @"CHILD:(\d+)\r?\n");
            if (match.Success) Pid.TrySetResult(int.Parse(match.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture));
            return ValueTask.CompletedTask;
        }
    }
    private sealed class TestFolder : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("jts-worker-acceptance-");
        internal string Path => _directory.FullName;
        public void Dispose() => _directory.Delete(true);
    }
}

internal sealed class WindowsWorkerFactAttribute : FactAttribute
{
    public WindowsWorkerFactAttribute()
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10) || !Environment.Is64BitProcess)
            Skip = "Requires real 64-bit Windows 10 ESU / 11; no native execution evidence on this host.";
        else if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("JTS_EXECUTION_TEST_WORKER_SID")))
            Skip = "Set JTS_EXECUTION_TEST_WORKER_SID only in the explicitly provisioned standard-account test host.";
    }
}
