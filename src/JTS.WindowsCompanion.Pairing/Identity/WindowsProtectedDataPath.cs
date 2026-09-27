namespace JTS.WindowsCompanion.Pairing;

/// <summary>Preflight for an authority-owned state file and its SQLite/lease companions. Never changes ACLs.</summary>
public static class WindowsProtectedDataPath
{
    public static string Require(string path, string expectedAccountSid)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows authority storage is required.");
        var full = WindowsIdentityAccess.Require(path, expectedAccountSid);
        foreach (var suffix in new[] { "-wal", "-shm" }) WindowsIdentityAccess.Require(full + suffix, expectedAccountSid);
        return full;
    }
}
