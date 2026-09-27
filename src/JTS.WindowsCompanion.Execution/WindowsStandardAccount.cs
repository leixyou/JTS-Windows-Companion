namespace JTS.WindowsCompanion.Execution;

/// <summary>Shared account preflight for separately installed low-privilege endpoints; does not execute a task.</summary>
public static class WindowsStandardAccount
{
    public static void VerifyCurrent(string expectedAccountSid)
    {
        WorkerAccountPolicy.ValidateConfiguredSid(expectedAccountSid);
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess)
            throw new PlatformNotSupportedException("A 64-bit Windows standard-account endpoint is required.");
        WindowsWorkerToken.Verify(WindowsNative.GetCurrentProcess(), expectedAccountSid);
    }

    /// <summary>Explicit service-start reduction of this process only, followed by the unchanged strict account check.</summary>
    public static void RestrictServiceCurrent(string expectedAccountSid)
    {
        WorkerAccountPolicy.ValidateConfiguredSid(expectedAccountSid);
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess)
            throw new PlatformNotSupportedException("A 64-bit Windows standard-account service is required.");
        WindowsWorkerToken.RestrictServiceCurrent(expectedAccountSid);
    }
}
