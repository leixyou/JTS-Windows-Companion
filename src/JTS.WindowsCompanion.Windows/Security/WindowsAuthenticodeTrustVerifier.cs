using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace JTS.WindowsCompanion.Windows.Security;

public sealed record SignedBinaryTrustPolicy(
    string PublisherSubject,
    string CertificateSha256,
    string ExpectedFileName)
{
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(PublisherSubject)
            || PublisherSubject.Length > 512
            || CertificateSha256.Length != 64
            || !CertificateSha256.All(char.IsAsciiHexDigit)
            || string.IsNullOrWhiteSpace(ExpectedFileName)
            || ExpectedFileName != Path.GetFileName(ExpectedFileName))
        {
            throw new ArgumentException("The signed-binary trust policy is invalid.");
        }
    }
}

public interface IExecutableTrustVerifier
{
    void Verify(string executablePath, SignedBinaryTrustPolicy policy);
}

public sealed class WindowsAuthenticodeTrustVerifier : IExecutableTrustVerifier
{
    public SignedBinaryTrustPolicy CreateSameSignerPolicy(
        string signedExecutablePath,
        string expectedTargetFileName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(signedExecutablePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedTargetFileName);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Authenticode verification is available only on Windows.");
        }

        return CreateSameSignerPolicyWindows(signedExecutablePath, expectedTargetFileName);
    }

    public void Verify(string executablePath, SignedBinaryTrustPolicy policy)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        ArgumentNullException.ThrowIfNull(policy);
        policy.Validate();
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Authenticode verification is available only on Windows.");
        }

        VerifyWindows(executablePath, policy);
    }

    [SupportedOSPlatform("windows")]
    private static void VerifyWindows(string executablePath, SignedBinaryTrustPolicy policy)
    {
        var fullPath = Path.GetFullPath(executablePath);
        if (!File.Exists(fullPath)
            || !string.Equals(Path.GetFileName(fullPath), policy.ExpectedFileName, StringComparison.OrdinalIgnoreCase)
            || (File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new UnauthorizedAccessException("The trusted executable is missing or has an unexpected path.");
        }

        var trustResult = VerifyEmbeddedSignature(fullPath);
        if (trustResult != 0)
        {
            throw new UnauthorizedAccessException($"Authenticode verification failed with status 0x{trustResult:X8}.");
        }

        using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(fullPath));
        var certificateHash = certificate.GetCertHashString(HashAlgorithmName.SHA256);
        if (!string.Equals(certificate.Subject, policy.PublisherSubject, StringComparison.Ordinal)
            || !string.Equals(certificateHash, policy.CertificateSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException("The executable signer does not match the installed publisher policy.");
        }
    }

    [SupportedOSPlatform("windows")]
    private static SignedBinaryTrustPolicy CreateSameSignerPolicyWindows(
        string signedExecutablePath,
        string expectedTargetFileName)
    {
        var fullPath = Path.GetFullPath(signedExecutablePath);
        if (!File.Exists(fullPath)
            || (File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0
            || VerifyEmbeddedSignature(fullPath) != 0)
        {
            throw new UnauthorizedAccessException("The running JTS executable does not have a trusted Authenticode signature.");
        }

        using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(fullPath));
        var policy = new SignedBinaryTrustPolicy(
            certificate.Subject,
            certificate.GetCertHashString(HashAlgorithmName.SHA256),
            expectedTargetFileName);
        policy.Validate();
        return policy;
    }

    [SupportedOSPlatform("windows")]
    private static uint VerifyEmbeddedSignature(string filePath)
    {
        var filePathPointer = Marshal.StringToCoTaskMemUni(filePath);
        var fileInfo = new WinTrustFileInfo
        {
            StructSize = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
            FilePath = filePathPointer,
        };
        var fileInfoPointer = Marshal.AllocCoTaskMem(Marshal.SizeOf<WinTrustFileInfo>());
        Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);
        var data = new WinTrustData
        {
            StructSize = (uint)Marshal.SizeOf<WinTrustData>(),
            UIChoice = WinTrustDataUIChoice.None,
            RevocationChecks = WinTrustDataRevocationChecks.WholeChain,
            UnionChoice = WinTrustDataChoice.File,
            FileOrCatalogOrBlobOrSigner = fileInfoPointer,
            StateAction = WinTrustDataStateAction.Verify,
            ProviderFlags = 0x00000080 | 0x00002000,
        };
        try
        {
            var action = WinTrustActionGenericVerifyV2;
            var result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            return unchecked((uint)result);
        }
        finally
        {
            data.StateAction = WinTrustDataStateAction.Close;
            var action = WinTrustActionGenericVerifyV2;
            _ = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            Marshal.FreeCoTaskMem(fileInfoPointer);
            Marshal.FreeCoTaskMem(filePathPointer);
        }
    }

    private static readonly Guid WinTrustActionGenericVerifyV2 = new(
        0x00AAC56B,
        0xCD44,
        0x11D0,
        0x8C,
        0xC2,
        0x00,
        0xC0,
        0x4F,
        0xC2,
        0x95,
        0xEE);

    [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true)]
    private static extern int WinVerifyTrust(
        IntPtr windowHandle,
        [In] ref Guid actionId,
        [In, Out] ref WinTrustData trustData);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint StructSize;
        public IntPtr FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public uint StructSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SIPClientData;
        public WinTrustDataUIChoice UIChoice;
        public WinTrustDataRevocationChecks RevocationChecks;
        public WinTrustDataChoice UnionChoice;
        public IntPtr FileOrCatalogOrBlobOrSigner;
        public WinTrustDataStateAction StateAction;
        public IntPtr StateData;
        public string? URLReference;
        public uint ProviderFlags;
        public uint UIContext;
    }

    private enum WinTrustDataUIChoice : uint
    {
        None = 2,
    }

    private enum WinTrustDataRevocationChecks : uint
    {
        WholeChain = 1,
    }

    private enum WinTrustDataChoice : uint
    {
        File = 1,
    }

    private enum WinTrustDataStateAction : uint
    {
        Verify = 1,
        Close = 2,
    }
}
