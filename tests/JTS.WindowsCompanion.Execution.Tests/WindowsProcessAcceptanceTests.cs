using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using JTS.WindowsCompanion.Runtime;
using Xunit;

namespace JTS.WindowsCompanion.Execution.Tests;

// These execute real scripts only on an explicitly selected, provisioned standard-account Windows test host.
public sealed class WindowsProcessAcceptanceTests
{
    [WindowsWorkerFact]
    public async Task RealPowerShellPreservesUnicodeAndNonzeroExit()
    {
        await WithTestFolderAsync(async folder =>
        {
            var executor = new StandardAccountPowerShellExecutor(Environment.GetEnvironmentVariable("JTS_EXECUTION_TEST_WORKER_SID")!);
            var job = ExecutionContractTests.Job("[Console]::Out.Write('中文 😀'); [Console]::Error.Write('错误 stderr 🚀'); exit 7", folder.Path);
            var sink = new NativeOutputSink();
            await WithRunningJobAsync(executor, job, sink, async (run, _) =>
            {
                var result = await run;
                Assert.False(result.Success); Assert.Equal("POWERSHELL_EXIT_NONZERO", result.ResultCode);
                var output = sink.Text;
                Assert.Contains("中文 😀", output); Assert.Contains("错误 stderr 🚀", output);
                Assert.DoesNotContain("CLIXML", output);
            });
            var success = ExecutionContractTests.Job("""
                if (-not (Test-Path -LiteralPath '.')) { throw 'working-directory-missing' }
                $null = Get-ChildItem -LiteralPath '.'
                $null = Get-Date
                Write-Output 'done'
                exit 0
                """, folder.Path);
            var successSink = new NativeOutputSink();
            await WithRunningJobAsync(executor, success, successSink, async (run, _) =>
            {
                Assert.True((await run).Success);
                var output = successSink.Text;
                Assert.Contains("done", output); Assert.DoesNotContain("CLIXML", output);
            });
            var errorJob = ExecutionContractTests.Job("Write-Error '中文é🚀'", folder.Path);
            var errorSink = new NativeOutputSink();
            await WithRunningJobAsync(executor, errorJob, errorSink, async (run, _) =>
            {
                var result = await run;
                Assert.False(result.Success); Assert.Equal("POWERSHELL_EXIT_NONZERO", result.ResultCode);
                Assert.Contains("中文é🚀", errorSink.Text); Assert.DoesNotContain("CLIXML", errorSink.Text);
            });
            var continuedJob = ExecutionContractTests.Job(
                "Write-Error -ErrorAction Continue '中文é🚀'; Write-Output 'continued'", folder.Path);
            var continuedSink = new NativeOutputSink();
            await WithRunningJobAsync(executor, continuedJob, continuedSink, async (run, _) =>
            {
                Assert.True((await run).Success);
                Assert.Contains("中文é🚀", continuedSink.Text); Assert.Contains("continued", continuedSink.Text);
                Assert.DoesNotContain("CLIXML", continuedSink.Text);
            });
        });
    }
    [WindowsWorkerFact]
    public async Task CancellationKillsOrdinaryChildBeforeTerminalReceipt()
    {
        await WithTestFolderAsync(async folder =>
        {
            var executor = new StandardAccountPowerShellExecutor(Environment.GetEnvironmentVariable("JTS_EXECUTION_TEST_WORKER_SID")!);
            var job = ExecutionContractTests.Job("""
                $p = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList '-NoProfile -NonInteractive -Command Start-Sleep -Seconds 60' -PassThru
                [Console]::Out.WriteLine(('CHILD:' + $p.Id))
                Start-Sleep -Seconds 60
                """, folder.Path);
            var sink = new ChildPidSink();
            await WithRunningJobAsync(executor, job, sink, async (run, cancel) =>
            {
                var pid = await sink.Pid.Task.WaitAsync(TimeSpan.FromSeconds(10));
                using var child = Process.GetProcessById(pid);
                cancel.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.WaitAsync(TimeSpan.FromSeconds(5)));
                Assert.True(child.HasExited);
            });
        });
    }

    private static async Task WithRunningJobAsync(StandardAccountPowerShellExecutor executor, JobSubmission job,
        NativeOutputSink sink, Func<Task<JobExecutionResult>, CancellationTokenSource, Task> assertions)
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var run = executor.ExecuteAsync(job.Binding, job.Payload, sink, cancellation.Token).AsTask();
        Exception? failure = null;
        try { await assertions(run, cancellation); }
        catch (Exception error) { failure = error; }
        finally
        {
            // Cancellation and the awaited executor finally run before deleting
            // its working directory, including when PID observation times out.
            try { cancellation.Cancel(); }
            catch (Exception error) { failure = CombineFailures(failure, error); }
            try { await run.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
            catch (Exception error) { failure = CombineFailures(failure, error); }
        }
        if (failure is not null)
        {
            // These scripts contain only synthetic fixture data. Preserve a
            // bounded, escaped snapshot, including the honestly empty case.
            var output = sink.Text;
            throw new AggregateException("Native PowerShell fixture failed. Captured synthetic output: "
                + JsonSerializer.Serialize(output[..Math.Min(output.Length, 4096)]), failure);
        }
    }

    private static async Task WithTestFolderAsync(Func<TestFolder, Task> test)
    {
        var folder = new TestFolder();
        Exception? failure = null;
        try { await test(folder); }
        catch (Exception error) { failure = error; }
        finally
        {
            try { await folder.DeleteAsync(); }
            catch (Exception error) { failure = CombineFailures(failure, error); }
        }
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
    }

    private static Exception CombineFailures(Exception? primary, Exception cleanup) =>
        primary is null ? cleanup : ReferenceEquals(primary, cleanup) ? primary :
        new AggregateException("Native execution failed and cleanup also failed; both causes are retained.", primary, cleanup);
    private class NativeOutputSink : IJobOutputSink
    {
        private readonly MemoryStream _bytes = new();
        internal string Text { get { lock (_bytes) return Encoding.UTF8.GetString(_bytes.ToArray()); } }
        public virtual ValueTask AppendAsync(ReadOnlyMemory<byte> output, CancellationToken cancellationToken)
        {
            lock (_bytes) _bytes.Write(output.Span);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class ChildPidSink : NativeOutputSink
    {
        internal TaskCompletionSource<int> Pid { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override ValueTask AppendAsync(ReadOnlyMemory<byte> output, CancellationToken cancellationToken)
        {
            base.AppendAsync(output, cancellationToken);
            var match = Regex.Match(Text, @"CHILD:(\d+)\r?\n");
            if (match.Success) Pid.TrySetResult(int.Parse(match.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture));
            return ValueTask.CompletedTask;
        }
    }
    private sealed class TestFolder
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("jts-worker-acceptance-");
        internal string Path => _directory.FullName;
        internal async Task DeleteAsync()
        {
            for (var attempt = 0; ; attempt++)
            {
                try { _directory.Delete(true); return; }
                catch (IOException) when (attempt < 19) { await Task.Delay(50); }
            }
        }
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
