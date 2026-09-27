using JTS.WindowsCompanion.Windows.Managed;
using JTS.WindowsCompanion.Windows.Security;

namespace JTS.WindowsCompanion.Tests;

public sealed class ManagedServiceIdentityTests
{
    private const int ServiceProcessId = 4816;
    private const string ServicePath =
        @"C:\Program Files\JTS Terminal\Windows Companion\Managed\JTS.WindowsCompanion.ManagedService.exe";

    [Fact]
    public void Attestor_AcceptsExactScmProcessAndAuthenticatedRelease()
    {
        var source = new FixedIdentitySource(ValidIdentity());
        var trust = new RecordingTrustVerifier();
        var attestor = CreateAttestor(source, trust);

        attestor.Attest(ServiceProcessId);

        Assert.Equal(ManagedServiceInstallation.ServiceName, source.RequestedServiceName);
        Assert.Equal(ServicePath, trust.VerifiedPath);
        Assert.Equal(ManagedServiceInstallation.ExecutableFileName, trust.VerifiedFileName);
    }

    [Fact]
    public void Attestor_RejectsWrongRegisteredService()
    {
        var identity = ValidIdentity() with { RegisteredServiceName = "JTSWindowsCompanionImpostor" };

        AssertRejected(identity);
    }

    [Fact]
    public void Attestor_RejectsPipePidThatDoesNotMatchScmPid()
    {
        var attestor = CreateAttestor(new FixedIdentitySource(ValidIdentity()), new RecordingTrustVerifier());

        Assert.Throws<UnauthorizedAccessException>(() => attestor.Attest(ServiceProcessId + 1));
    }

    [Fact]
    public void Attestor_RejectsProcessPidThatDoesNotMatchScmPid()
    {
        var identity = ValidIdentity() with { ProcessId = ServiceProcessId + 1 };

        AssertRejected(identity);
    }

    [Theory]
    [InlineData(@"C:\Program Files\JTS Terminal\Windows Companion\Managed\other.exe", ServicePath)]
    [InlineData(ServicePath, @"C:\Temp\JTS.WindowsCompanion.ManagedService.exe")]
    [InlineData(ServicePath, ServicePath)]
    [InlineData(ServicePath + " --console", ServicePath)]
    public void Attestor_RejectsWrongRegisteredOrRunningPath(
        string registeredPath,
        string processPath)
    {
        var identity = ValidIdentity() with
        {
            RegisteredExecutablePath = registeredPath,
            ProcessExecutablePath = processPath,
        };

        AssertRejected(identity);
    }

    [Fact]
    public void Attestor_RejectsNonLocalSystemSid()
    {
        var identity = ValidIdentity() with { ProcessUserSid = "S-1-5-21-1000" };

        AssertRejected(identity);
    }

    [Fact]
    public void Attestor_RejectsNonZeroSession()
    {
        var identity = ValidIdentity() with { ProcessSessionId = 2 };

        AssertRejected(identity);
    }

    [Fact]
    public void Attestor_RejectsInteractiveToken()
    {
        var identity = ValidIdentity() with { HasInteractiveToken = true };

        AssertRejected(identity);
    }

    [Fact]
    public void Attestor_RejectsUnknownIdentityField()
    {
        var trust = new RecordingTrustVerifier();
        var identity = ValidIdentity() with { HasServiceToken = null };
        var attestor = CreateAttestor(new FixedIdentitySource(identity), trust);

        Assert.Throws<UnauthorizedAccessException>(() => attestor.Attest(ServiceProcessId));
        Assert.Null(trust.VerifiedPath);
    }

    [Fact]
    public void Attestor_RejectsUntrustedReleaseExecutable()
    {
        var trust = new RecordingTrustVerifier
        {
            Failure = new UnauthorizedAccessException("not in the authenticated release"),
        };
        var attestor = CreateAttestor(new FixedIdentitySource(ValidIdentity()), trust);

        Assert.Throws<UnauthorizedAccessException>(() => attestor.Attest(ServiceProcessId));
    }

    [Fact]
    public void ServiceStartupAttestor_AcceptsOnlyScmStartPendingIdentity()
    {
        var identity = ValidIdentity() with { ServiceState = ManagedServiceScmState.StartPending };
        var policy = Policy() with { ExpectedState = ManagedServiceScmState.StartPending };
        var attestor = new ManagedServiceProcessAttestor(
            policy,
            new FixedIdentitySource(identity),
            new RecordingTrustVerifier());

        attestor.Attest(ServiceProcessId);
    }

    [Theory]
    [InlineData("NetworkService", true, ManagedServiceScmState.Running, false, true)]
    [InlineData("LocalSystem", false, ManagedServiceScmState.Running, false, true)]
    [InlineData("LocalSystem", true, ManagedServiceScmState.StartPending, false, true)]
    [InlineData("LocalSystem", true, ManagedServiceScmState.Running, true, true)]
    [InlineData("LocalSystem", true, ManagedServiceScmState.Running, false, false)]
    public void Attestor_RejectsWrongScmOrNonInteractiveServiceContext(
        string account,
        bool ownProcess,
        ManagedServiceScmState state,
        bool interactive,
        bool serviceToken)
    {
        var identity = ValidIdentity() with
        {
            ConfiguredAccountName = account,
            IsOwnProcessService = ownProcess,
            ServiceState = state,
            HasInteractiveToken = interactive,
            HasServiceToken = serviceToken,
        };

        AssertRejected(identity);
    }

    [Fact]
    public void StartupArguments_ProductionModeRejectsConsoleHost()
    {
        Assert.Throws<ArgumentException>(() =>
            ManagedServiceStartupArguments.Parse(["--console"], debugConsoleHostEnabled: false));
        Assert.Equal(
            ManagedServiceStartupMode.Service,
            ManagedServiceStartupArguments.Parse([], debugConsoleHostEnabled: false));
    }

    [Fact]
    public void StartupArguments_DebugConsoleRequiresExplicitBuildGate()
    {
        Assert.Equal(
            ManagedServiceStartupMode.DebugConsole,
            ManagedServiceStartupArguments.Parse(["--console"], debugConsoleHostEnabled: true));
    }

    [Fact]
    public void WindowsIdentitySource_FailsClosedOffWindows()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var source = new WindowsManagedServiceProcessIdentitySource();
        Assert.Throws<PlatformNotSupportedException>(() =>
            source.Capture(ManagedServiceInstallation.ServiceName));
    }

    private static ManagedServiceProcessAttestor CreateAttestor(
        IManagedServiceProcessIdentitySource source,
        IReleaseExecutableTrustVerifier trust) =>
        new(Policy(), source, trust);

    private static void AssertRejected(ManagedServiceProcessIdentity identity)
    {
        var trust = new RecordingTrustVerifier();
        var attestor = CreateAttestor(new FixedIdentitySource(identity), trust);

        Assert.Throws<UnauthorizedAccessException>(() => attestor.Attest(ServiceProcessId));
        Assert.Null(trust.VerifiedPath);
    }

    private static ManagedServiceIdentityPolicy Policy() =>
        new(
            ManagedServiceInstallation.ServiceName,
            ServicePath,
            ManagedServiceInstallation.ExecutableFileName,
            ManagedServiceScmState.Running);

    private static ManagedServiceProcessIdentity ValidIdentity() =>
        new(
            ManagedServiceInstallation.ServiceName,
            ServiceProcessId,
            $"\"{ServicePath}\"",
            ManagedServiceIdentityPolicy.LocalSystemAccountName,
            true,
            ManagedServiceScmState.Running,
            ServiceProcessId,
            ServicePath,
            ManagedServiceIdentityPolicy.LocalSystemSid,
            ManagedServiceIdentityPolicy.ServiceSessionId,
            false,
            true);

    private sealed class FixedIdentitySource(ManagedServiceProcessIdentity identity)
        : IManagedServiceProcessIdentitySource
    {
        public string? RequestedServiceName { get; private set; }

        public ManagedServiceProcessIdentity Capture(string registeredServiceName)
        {
            RequestedServiceName = registeredServiceName;
            return identity;
        }
    }

    private sealed class RecordingTrustVerifier : IReleaseExecutableTrustVerifier
    {
        public Exception? Failure { get; init; }

        public string? VerifiedPath { get; private set; }

        public string? VerifiedFileName { get; private set; }

        public void Verify(string executablePath, string expectedFileName)
        {
            VerifiedPath = executablePath;
            VerifiedFileName = expectedFileName;
            if (Failure is not null)
            {
                throw Failure;
            }
        }

        public FileStream OpenVerifiedFile(string executablePath, string expectedFileName) =>
            throw new NotSupportedException("This identity attestation test does not launch an executable.");
    }
}
