using System.Runtime.InteropServices;
using System.Text;
using Xunit;

namespace JTS.WindowsCompanion.WorkerService.Tests;

public sealed class ServicePolicyTests
{
    internal const string Authority = "S-1-5-80-1-2-3-4-5", Worker = "S-1-5-21-1-2-3-1001";
    internal static WorkerServiceInstallation Installation() => new(@"C:\Program Files\JTS Companion\JTS.WindowsCompanion.WorkerRunner.exe", @".\JTSWorker25", Worker);
    private static ServiceFacts Good()
    {
        var install = Installation();
        return new ServiceFacts(0x10, 3, '"' + install.ExecutablePath + "\" --service", install.AccountName, install.AccountSid,
            ["SeChangeNotifyPrivilege"], 1, false, false, 0, false,
            new SecurityFacts(WorkerServicePolicy.SystemSid, true,
                [new(WorkerServicePolicy.SystemSid, 0xF01FF, true), new(WorkerServicePolicy.AdminSid, 0xF01FF, true), new(Authority, WorkerServicePolicy.AuthorityServiceRights, true)]));
    }
    [Fact]
    public void ExactOnDemandStandardAccountServiceIsAccepted() => WorkerServicePolicy.Validate(Installation(), Authority, Good());
    [Theory]
    [InlineData("auto")]
    [InlineData("shared")]
    [InlineData("interactive")]
    [InlineData("system")]
    [InlineData("arguments")]
    [InlineData("argument-case")]
    [InlineData("unquoted")]
    [InlineData("recovery")]
    [InlineData("failure-flag")]
    [InlineData("trigger")]
    [InlineData("delay")]
    [InlineData("privileges")]
    [InlineData("default-privileges")]
    [InlineData("service-sid")]
    public void ConfigurationExpansionOrAutomaticRestartIsRejected(string mutation)
    {
        var good = Good();
        var changed = mutation switch
        {
            "auto" => good with { StartType = 2 }, "shared" => good with { Type = 0x20 }, "interactive" => good with { Type = 0x110 },
            "system" => good with { AccountName = "LocalSystem", AccountSid = "S-1-5-18" },
            "arguments" => good with { Command = good.Command + " extra" }, "unquoted" => good with { Command = good.Command.Replace("\"", "") },
            "argument-case" => good with { Command = good.Command.Replace("--service", "--SERVICE", StringComparison.Ordinal) },
            "recovery" => good with { RecoveryActions = true }, "failure-flag" => good with { FailureFlag = true },
            "trigger" => good with { Triggers = 1 }, "delay" => good with { DelayedStart = true },
            "privileges" => good with { RequiredPrivileges = ["SeChangeNotifyPrivilege", "SeImpersonatePrivilege"] },
            "default-privileges" => good with { RequiredPrivileges = [] }, "service-sid" => good with { ServiceSidType = 0 },
            _ => throw new InvalidOperationException(),
        };
        Assert.Throws<WorkerServiceException>(() => WorkerServicePolicy.Validate(Installation(), Authority, changed));
    }
    [Theory]
    [InlineData("write-config")]
    [InlineData("worker-start")]
    [InlineData("everyone")]
    [InlineData("owner")]
    [InlineData("inherit")]
    [InlineData("missing")]
    public void WorkerOrOtherAccountsCannotControlOrReconfigureService(string mutation)
    {
        var good = Good(); var security = good.Security;
        security = mutation switch
        {
            "write-config" => security with { Entries = [new(Authority, WorkerServicePolicy.AuthorityServiceRights | 2, true)] },
            "worker-start" => security with { Entries = [.. security.Entries, new(Worker, 0x10, true)] },
            "everyone" => security with { Entries = [.. security.Entries, new("S-1-1-0", 0x10, true)] },
            "owner" => security with { Owner = Worker }, "inherit" => security with { Protected = false },
            "missing" => security with { Entries = [] }, _ => throw new InvalidOperationException(),
        };
        Assert.Throws<WorkerServiceException>(() => WorkerServicePolicy.Validate(Installation(), Authority, good with { Security = security }));
    }
    [Fact]
    public void ParentSiblingCreationIsNotConfusedWithReplacementOfProtectedProgram()
    {
        var security = new SecurityFacts(WorkerServicePolicy.SystemSid, false, [new("S-1-5-11", 4, true)]);
        WorkerServicePolicy.ValidateProgramObject(security, canCreateContent: false);
        Assert.Throws<WorkerServiceException>(() => WorkerServicePolicy.ValidateProgramObject(security, canCreateContent: true));
        foreach (var right in new[] { 2, 0x40, 0x10000, 0x40000, 0x80000, 0x40000000, 0x10000000 })
            Assert.Throws<WorkerServiceException>(() => WorkerServicePolicy.ValidateProgramObject(security with { Entries = [new(Worker, right, true)] }, true));
        Assert.Throws<WorkerServiceException>(() => WorkerServicePolicy.ValidateProgramObject(security with { Owner = Worker }, false));
    }
    [Fact]
    public void RejectsRemoteAccountAdminAccountAndUnexpectedWorkerBinary()
    {
        var executable = Installation().ExecutablePath;
        Assert.Throws<ArgumentException>(() => new WorkerServiceInstallation(executable, @"DOMAIN\worker", Worker));
        Assert.Throws<ArgumentException>(() => new WorkerServiceInstallation(executable, @".\worker", "S-1-5-21-1-2-3-500"));
        Assert.Throws<ArgumentException>(() => new WorkerServiceInstallation(@"C:\cmd.exe", @".\worker", Worker));
        Assert.Throws<ArgumentException>(() => new WorkerServiceInstallation(@"\\server\JTS.WindowsCompanion.WorkerRunner.exe", @".\worker", Worker));
    }
    [Fact]
    public void NativeStringsMustStayWithinTheirReturnedBuffer()
    {
        var bytes = Encoding.Unicode.GetBytes("a\0b\0\0"); using var buffer = new ScmBuffer(bytes.Length);
        Marshal.Copy(bytes, 0, buffer.Pointer, bytes.Length);
        Assert.Equal(new[] { "a", "b" }, buffer.MultiString(buffer.Pointer));
        Assert.Throws<WorkerServiceException>(() => buffer.String(buffer.Pointer + bytes.Length));
        Assert.Throws<WorkerServiceException>(() => buffer.String(buffer.Pointer - 2));
        Marshal.Copy(Encoding.Unicode.GetBytes("abcde"), 0, buffer.Pointer, bytes.Length);
        Assert.Throws<WorkerServiceException>(() => buffer.String(buffer.Pointer));
    }
}
