using System.IO;
using JTS.WindowsCompanion.Windows.Security;

namespace JTS.WindowsCompanion.Windows.Managed;

public static class ManagedServiceInstallation
{
    public const string ServiceName = "JTSWindowsCompanionManaged";
    public const string ExecutableFileName = "JTS.WindowsCompanion.ManagedService.exe";

    public static string GetExpectedExecutablePath()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "The managed service installation path is available only on Windows.");
        }

        var programFiles = Environment.GetFolderPath(
            Environment.SpecialFolder.ProgramFiles,
            Environment.SpecialFolderOption.DoNotVerify);
        if (string.IsNullOrWhiteSpace(programFiles))
        {
            throw new InvalidOperationException("The protected Program Files directory is unavailable.");
        }

        return Path.GetFullPath(Path.Combine(
            programFiles,
            "JTS Terminal",
            "Windows Companion",
            "Managed",
            ExecutableFileName));
    }
}

public enum ManagedServiceScmState : uint
{
    Unknown = 0,
    Stopped = 1,
    StartPending = 2,
    StopPending = 3,
    Running = 4,
    ContinuePending = 5,
    PausePending = 6,
    Paused = 7,
}

public sealed record ManagedServiceProcessIdentity(
    string? RegisteredServiceName,
    int? ScmProcessId,
    string? RegisteredExecutablePath,
    string? ConfiguredAccountName,
    bool? IsOwnProcessService,
    ManagedServiceScmState? ServiceState,
    int? ProcessId,
    string? ProcessExecutablePath,
    string? ProcessUserSid,
    int? ProcessSessionId,
    bool? HasInteractiveToken,
    bool? HasServiceToken);

public sealed record ManagedServiceIdentityPolicy(
    string ServiceName,
    string ExpectedExecutablePath,
    string ExpectedFileName,
    ManagedServiceScmState ExpectedState)
{
    public const string LocalSystemSid = "S-1-5-18";
    public const string LocalSystemAccountName = "LocalSystem";
    public const int ServiceSessionId = 0;

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(ServiceName)
            || ServiceName.Length > 256
            || ServiceName.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_'))
            || string.IsNullOrWhiteSpace(ExpectedExecutablePath)
            || string.IsNullOrWhiteSpace(ExpectedFileName)
            || !string.Equals(
                GetFileName(ExpectedExecutablePath),
                ExpectedFileName,
                StringComparison.OrdinalIgnoreCase)
            || ExpectedState is not ManagedServiceScmState.StartPending and not ManagedServiceScmState.Running)
        {
            throw new ArgumentException("The managed service identity policy is invalid.");
        }
    }

    internal static string NormalizePath(string path) =>
        path.Trim().Replace('/', (char)0x5C).TrimEnd((char)0x5C);

    private static string GetFileName(string path)
    {
        var normalized = NormalizePath(path);
        var separator = normalized.LastIndexOf((char)0x5C);
        return separator >= 0 ? normalized[(separator + 1)..] : normalized;
    }
}

public interface IManagedServiceProcessIdentitySource
{
    ManagedServiceProcessIdentity Capture(string registeredServiceName);
}

public interface IManagedServiceProcessAttestor
{
    void Attest(int expectedProcessId);
}

public sealed class ManagedServiceProcessAttestor : IManagedServiceProcessAttestor
{
    private readonly ManagedServiceIdentityPolicy _policy;
    private readonly IManagedServiceProcessIdentitySource _identitySource;
    private readonly IReleaseExecutableTrustVerifier _trustVerifier;

    public ManagedServiceProcessAttestor(
        ManagedServiceIdentityPolicy policy,
        IManagedServiceProcessIdentitySource identitySource,
        IReleaseExecutableTrustVerifier trustVerifier)
    {
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _policy.Validate();
        _identitySource = identitySource ?? throw new ArgumentNullException(nameof(identitySource));
        _trustVerifier = trustVerifier ?? throw new ArgumentNullException(nameof(trustVerifier));
    }

    public void Attest(int expectedProcessId)
    {
        if (expectedProcessId <= 0)
        {
            throw Rejected();
        }

        ManagedServiceProcessIdentity identity;
        try
        {
            identity = _identitySource.Capture(_policy.ServiceName)
                ?? throw Rejected();
        }
        catch (UnauthorizedAccessException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw Rejected(exception);
        }

        if (!string.Equals(identity.RegisteredServiceName, _policy.ServiceName, StringComparison.Ordinal)
            || identity.ScmProcessId != expectedProcessId
            || identity.ProcessId != expectedProcessId
            || !MatchesRegisteredExecutable(identity.RegisteredExecutablePath, _policy.ExpectedExecutablePath)
            || !PathsEqual(identity.ProcessExecutablePath, _policy.ExpectedExecutablePath)
            || !string.Equals(
                identity.ConfiguredAccountName,
                ManagedServiceIdentityPolicy.LocalSystemAccountName,
                StringComparison.OrdinalIgnoreCase)
            || identity.IsOwnProcessService != true
            || identity.ServiceState != _policy.ExpectedState
            || !string.Equals(
                identity.ProcessUserSid,
                ManagedServiceIdentityPolicy.LocalSystemSid,
                StringComparison.Ordinal)
            || identity.ProcessSessionId != ManagedServiceIdentityPolicy.ServiceSessionId
            || identity.HasInteractiveToken != false
            || identity.HasServiceToken != true)
        {
            throw Rejected();
        }

        try
        {
            _trustVerifier.Verify(identity.ProcessExecutablePath!, _policy.ExpectedFileName);
        }
        catch (Exception exception) when (exception is not UnauthorizedAccessException)
        {
            throw Rejected(exception);
        }
    }

    private static bool MatchesRegisteredExecutable(string? registeredPath, string expectedPath)
    {
        if (string.IsNullOrWhiteSpace(registeredPath))
        {
            return false;
        }

        var candidate = registeredPath.Trim();
        var wasQuoted = false;
        if (candidate.Length >= 2 && candidate[0] == '"' && candidate[^1] == '"')
        {
            candidate = candidate[1..^1];
            wasQuoted = true;
        }

        return candidate.IndexOf('"') < 0
            && (wasQuoted || !candidate.Any(char.IsWhiteSpace))
            && PathsEqual(candidate, expectedPath);
    }

    private static bool PathsEqual(string? actual, string expected) =>
        !string.IsNullOrWhiteSpace(actual)
        && string.Equals(
            ManagedServiceIdentityPolicy.NormalizePath(actual),
            ManagedServiceIdentityPolicy.NormalizePath(expected),
            StringComparison.OrdinalIgnoreCase);

    private static UnauthorizedAccessException Rejected(Exception? innerException = null) =>
        new("The managed service process identity could not be attested.", innerException);
}

public static class ManagedServiceAttestationFactory
{
    public static IManagedServiceProcessAttestor CreateForAgent(string agentExecutablePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentExecutablePath);
        return Create(
            agentExecutablePath,
            ManagedServiceScmState.Running);
    }

    public static IManagedServiceProcessAttestor CreateForService(string serviceExecutablePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serviceExecutablePath);
        return Create(
            serviceExecutablePath,
            ManagedServiceScmState.StartPending);
    }

    private static IManagedServiceProcessAttestor Create(
        string referenceExecutablePath,
        ManagedServiceScmState expectedState)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Managed service process attestation is available only on Windows.");
        }

        var verifier = ReleaseManifestExecutableTrustVerifier.ForExecutable(referenceExecutablePath);
        return new ManagedServiceProcessAttestor(
            new ManagedServiceIdentityPolicy(
                ManagedServiceInstallation.ServiceName,
                ManagedServiceInstallation.GetExpectedExecutablePath(),
                ManagedServiceInstallation.ExecutableFileName,
                expectedState),
            new WindowsManagedServiceProcessIdentitySource(),
            verifier);
    }
}
