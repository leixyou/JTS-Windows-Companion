using System.Diagnostics;
using System.Text;
using JTS.WindowsCompanion.Elevation;
using JTS.WindowsCompanion.Files;
using JTS.WindowsCompanion.Shell;

namespace JTS.WindowsCompanion.Tests;

public sealed class PowerShellUtf8Tests
{
    private const string UnicodeText = "中文é🚀";
    private const string UnicodeScript = "$名字 = '中文é🚀'; [Console]::Out.Write($名字); [Console]::Error.Write($名字); exit 7";

    [Fact]
    public void LaunchContractUsesBomlessUtf8PipesAndOnlyAConstantEncodedBootstrap()
    {
        var start = new ProcessStartInfo { FileName = "powershell.exe" };
        PowerShellUtf8LaunchPlan.Configure(start);
        foreach (var encoding in new[] { start.StandardInputEncoding, start.StandardOutputEncoding, start.StandardErrorEncoding })
        {
            Assert.NotNull(encoding);
            Assert.Equal(65001, encoding.CodePage);
            Assert.Empty(encoding.GetPreamble());
        }
        Assert.Equal(["-NoLogo", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-EncodedCommand"],
            start.ArgumentList.Take(6).ToArray());
        Assert.Equal(7, start.ArgumentList.Count);
        Assert.Equal(PowerShellUtf8LaunchPlan.Bootstrap,
            Encoding.Unicode.GetString(Convert.FromBase64String(start.ArgumentList[^1])));
        Assert.DoesNotContain(UnicodeScript, string.Join(' ', start.ArgumentList));
        Assert.DoesNotContain("ExecutionPolicy", string.Join(' ', start.ArgumentList));
    }

    [WindowsIntegrationFact]
    public async Task CurrentUserPreservesUnicodeScriptStdoutStderrAndExplicitExitCode()
    {
        var result = await ExecuteAsync(UnicodeScript, approvedBrokerPath: false);
        AssertUnicode(result);
    }

    [WindowsIntegrationFact]
    public async Task ApprovedBrokerPathPreservesUnicodeScriptStdoutStderrAndExplicitExitCode()
    {
        // Exercises the real contained process/encoding path. Consent and UAC are independently tested.
        var result = await ExecuteAsync(UnicodeScript, approvedBrokerPath: true);
        AssertUnicode(result);
    }

    [WindowsIntegrationFact]
    public async Task BothExecutorsKeepTextErrorsAndNonterminatingErrorBehavior()
    {
        foreach (var broker in new[] { false, true })
        {
            var continued = await ExecuteAsync("Write-Error '中文é🚀'; Write-Output 'continued'", broker);
            Assert.Equal(0, continued.ExitCode);
            Assert.Contains("continued", continued.StandardOutput);
            Assert.Contains(UnicodeText, continued.StandardError);
            Assert.DoesNotContain("CLIXML", continued.StandardError);
            var terminated = await ExecuteAsync("throw '中文é🚀'", broker);
            Assert.Equal(1, terminated.ExitCode);
            Assert.Contains(UnicodeText, terminated.StandardError);
            var nativeFailure = await ExecuteAsync("& $env:COMSPEC /d /c 'exit 7'", broker);
            Assert.Equal(1, nativeFailure.ExitCode);
            var recovered = await ExecuteAsync("& $env:COMSPEC /d /c 'exit 7'; Write-Output 'continued'", broker);
            Assert.Equal(0, recovered.ExitCode);
            Assert.Contains("continued", recovered.StandardOutput);
        }
    }

    [WindowsIntegrationFact]
    public async Task BothExecutorsKeepUtf8ByteOutputLimits()
    {
        foreach (var broker in new[] { false, true })
        {
            var result = await ExecuteAsync("[Console]::Out.Write(('中' * 5000)); [Console]::Error.Write(('中' * 5000))", broker,
                maximumOutputBytes: 1024);
            Assert.Equal(0, result.ExitCode);
            Assert.True(result.OutputTruncated);
            foreach (var text in new[] { result.StandardOutput, result.StandardError })
            {
                Assert.NotEmpty(text);
                Assert.All(text, character => Assert.Equal('中', character));
                Assert.InRange(Encoding.UTF8.GetByteCount(text), 1, 512);
            }
        }
    }

    private static void AssertUnicode(ShellExecutionResult result)
    {
        Assert.Equal(7, result.ExitCode);
        Assert.Equal(UnicodeText, result.StandardOutput);
        Assert.Equal(UnicodeText, result.StandardError);
        Assert.False(result.TimedOut);
        Assert.False(result.OutputTruncated);
    }

    private static async Task<ShellExecutionResult> ExecuteAsync(string script, bool approvedBrokerPath,
        int maximumOutputBytes = 4096)
    {
        using var directory = new TemporaryDirectory();
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        if (approvedBrokerPath)
        {
            var executor = new ElevatedPowerShellExecutor(new TestApprovedBrokerVerifier());
            return await executor.ExecuteAsync(new ElevatedPowerShellActionDescriptor("utf8-test", script, directory.Path,
                15000, maximumOutputBytes, new Dictionary<string, string>(),
                [new ResolvedElevationDataScope("test", directory.Path, ElevationScopeAccess.ReadWrite)]), cancellation.Token);
        }
        var policy = new CurrentUserShellPolicy(new FileSandbox([new FileRoot("test", directory.Path)]));
        return await new CurrentUserPowerShellExecutor(policy).ExecuteAsync(
            new ShellExecutionRequest(script, "test", ".", 15000, maximumOutputBytes), cancellation.Token);
    }

    private sealed class TestApprovedBrokerVerifier : IProcessElevationVerifier
    {
        public bool IsElevated => true;
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("jts-utf8-");
        public string Path => _directory.FullName;
        public void Dispose() => _directory.Delete(recursive: true);
    }
}
