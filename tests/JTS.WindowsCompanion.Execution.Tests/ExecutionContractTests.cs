using System.Text;
using System.Text.Json;
using JTS.WindowsCompanion.Runtime;
using Xunit;

namespace JTS.WindowsCompanion.Execution.Tests;

public sealed class ExecutionContractTests
{
    internal const string WorkerSid = "S-1-5-21-123-456-789-1001";
    internal static JobSubmission Job(string script = "Write-Output 'hello'", string directory = @"C:\Work")
        => FromBytes(JsonSerializer.SerializeToUtf8Bytes(new { version = 1, script, workingDirectory = directory }));
    private static JobSubmission FromBytes(byte[] payload, string kind = "powershell.v1")
        => new(Guid.NewGuid(), kind, new string('a', 64), Guid.NewGuid(), DateTimeOffset.UtcNow.AddMinutes(1), payload);

    [Fact]
    public void AcceptsExactVersionedPayloadWithoutAddingScriptToDiagnostics()
    {
        var job = Job("Write-Output '中文 secret-marker'");
        var request = PowerShellRequest.Parse(job.Binding, job.Payload);
        Assert.Equal(@"C:\Work", request.WorkingDirectory);
        Assert.Contains("secret-marker", request.Script);
        Assert.DoesNotContain("secret-marker", request.ToString());
    }
    [Fact]
    public void ExactDefaultDirectoryIsDeferredToProtectedSharedRoot()
    {
        var job = Job(directory: ".");
        Assert.Equal(".", PowerShellRequest.Parse(job.Binding, job.Payload).WorkingDirectory);
        foreach (var path in new[] { "./", ".\\", "..", "./folder", "folder/.." })
        { var invalid = Job(directory: path); Assert.Throws<JobRuntimeException>(() => PowerShellRequest.Parse(invalid.Binding, invalid.Payload)); }
    }
    [Theory]
    [InlineData("{}")]
    [InlineData("""{"version":1,"script":"x","workingDirectory":"C:\\Work","elevate":true}""")]
    [InlineData("""{"version":1,"version":1,"script":"x","workingDirectory":"C:\\Work"}""")]
    [InlineData("""{"version":2,"script":"x","workingDirectory":"C:\\Work"}""")]
    [InlineData("""{"version":1,"script":1,"workingDirectory":"C:\\Work"}""")]
    [InlineData("null")]
    public void RejectsMalformedOrExtendedPayload(string json)
    {
        var job = FromBytes(Encoding.UTF8.GetBytes(json));
        Assert.Equal("JOB_POWERSHELL_PAYLOAD_INVALID", Assert.Throws<JobRuntimeException>(() => PowerShellRequest.Parse(job.Binding, job.Payload)).Code);
    }
    [Theory]
    [InlineData(@"\\server\share")]
    [InlineData(@"\\?\C:\Work")]
    [InlineData(@"C:Work")]
    [InlineData(@"C:\Work\..\Other")]
    [InlineData(@"C:\Work:stream")]
    [InlineData(@"C:\Work.")]
    [InlineData(@"C:\Work ")]
    [InlineData(@"C:\\Work")]
    [InlineData("/tmp")]
    public void RejectsNonCanonicalLocalDirectory(string directory)
    {
        var job = Job(directory: directory);
        Assert.Throws<JobRuntimeException>(() => PowerShellRequest.Parse(job.Binding, job.Payload));
    }
    [Fact]
    public void RejectsOversizeScriptNullCharactersWrongKindAndHash()
    {
        foreach (var script in new[] { " ", "x\0y", new string('x', 48 * 1024 + 1), new string('中', 16 * 1024 + 1) })
        {
            var job = Job(script);
            Assert.Throws<JobRuntimeException>(() => PowerShellRequest.Parse(job.Binding, job.Payload));
        }
        var valid = Job();
        Assert.Throws<JobRuntimeException>(() => PowerShellRequest.Parse(valid.Binding with { Kind = "shell" }, valid.Payload));
        Assert.Throws<JobRuntimeException>(() => PowerShellRequest.Parse(valid.Binding with { PayloadSha256 = new string('0', 64) }, valid.Payload));
    }
    [Fact]
    public void UsesConstantBootstrapWithNoProfileOrExecutionPolicyBypass()
    {
        var arguments = PowerShellLaunchPlan.Arguments;
        const string prefix = "-NoLogo -NoProfile -NonInteractive -OutputFormat Text -Command \"";
        Assert.StartsWith(prefix, arguments);
        Assert.EndsWith("\"", arguments);
        Assert.DoesNotContain('"', PowerShellLaunchPlan.Bootstrap);
        Assert.Equal(PowerShellLaunchPlan.Bootstrap.ReplaceLineEndings(" "), arguments[prefix.Length..^1]);
        Assert.DoesNotContain("EncodedCommand", arguments);
        Assert.DoesNotContain("ExecutionPolicy", arguments);
        Assert.Contains("[Console]::In.ReadToEnd()", PowerShellLaunchPlan.Bootstrap);
    }
    [Fact]
    public void LaunchEnvironmentIsAnExactAllowlistWithNoParentSecretOrSearchPathInheritance()
    {
        var block = PowerShellLaunchPlan.EnvironmentBlock(@"C:\Windows\System32", @"C:\Windows", @"C:\Users\Worker", @"C:\Users\Worker\AppData\Local");
        Assert.EndsWith("\0\0", block);
        var fields = block.TrimEnd('\0').Split('\0').Select(v => v.Split('=', 2)).ToDictionary(v => v[0], v => v[1]);
        Assert.Equal(10, fields.Count);
        Assert.Equal(@"C:\Windows\System32;C:\Windows;C:\Windows\System32\WindowsPowerShell\v1.0", fields["PATH"]);
        Assert.Equal(@"C:\Windows\System32\cmd.exe", fields["COMSPEC"]);
        Assert.Equal(@"C:\Windows\System32\WindowsPowerShell\v1.0\Modules", fields["PSModulePath"]);
        Assert.False(fields.ContainsKey("COR_ENABLE_PROFILING"));
        Assert.Throws<InvalidOperationException>(() => PowerShellLaunchPlan.EnvironmentBlock(@"C:\Windows\System32", @"C:\Windows", @"\\server\profile", @"C:\Temp"));
    }
    [Fact]
    public void AccountPolicyRejectsWrongSidAdminDenyOnlyGroupsAndDangerousDisabledPrivileges()
    {
        var good = new WorkerTokenFacts(WorkerSid, false, 8192, ["S-1-5-32-545"], ["SeChangeNotifyPrivilege"]);
        WorkerAccountPolicy.Validate(WorkerSid, good);
        foreach (var bad in new[]
        {
            good with { UserSid = "S-1-5-18" }, good with { Elevated = true }, good with { IntegrityRid = 12288 },
            good with { Groups = ["S-1-5-32-544"] }, good with { Privileges = ["SeImpersonatePrivilege"] },
            good with { Privileges = ["SeDebugPrivilege"] }, good with { Privileges = ["SeAssignPrimaryTokenPrivilege"] },
        }) Assert.Throws<InvalidOperationException>(() => WorkerAccountPolicy.Validate(WorkerSid, bad));
    }
    [Theory]
    [InlineData("S-1-5-18")]
    [InlineData("S-1-5-19")]
    [InlineData("S-1-5-21-123-456-789-500")]
    [InlineData("S-1-5-21-123-456-789-01001")]
    [InlineData("worker")]
    public void RejectsNonDedicatedAccountConfiguration(string sid)
        => Assert.Throws<ArgumentException>(() => WorkerAccountPolicy.ValidateConfiguredSid(sid));

    [Fact]
    public void NativeEntryHasNoNonWindowsFallback()
    {
        if (!OperatingSystem.IsWindows())
            Assert.Throws<PlatformNotSupportedException>(() => new StandardAccountPowerShellExecutor(WorkerSid));
    }
}
