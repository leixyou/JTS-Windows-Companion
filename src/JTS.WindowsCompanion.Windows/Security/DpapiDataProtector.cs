using System.ComponentModel;
using System.Runtime.InteropServices;
using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.Windows.Security;

public sealed class DpapiDataProtector : IDataProtector
{
    private const uint CryptProtectUiForbidden = 0x1;

    public byte[] Protect(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> entropy)
    {
        EnsureWindows();
        return Transform(plaintext, entropy, protect: true);
    }

    public byte[] Unprotect(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> entropy)
    {
        EnsureWindows();
        return Transform(ciphertext, entropy, protect: false);
    }

    private static byte[] Transform(ReadOnlySpan<byte> input, ReadOnlySpan<byte> entropy, bool protect)
    {
        var inputBlob = NativeBlob.From(input);
        var entropyBlob = NativeBlob.From(entropy);
        NativeBlob outputBlob = default;
        try
        {
            var succeeded = protect
                ? NativeMethods.CryptProtectData(
                    ref inputBlob,
                    null,
                    ref entropyBlob,
                    0,
                    0,
                    CryptProtectUiForbidden,
                    out outputBlob)
                : NativeMethods.CryptUnprotectData(
                    ref inputBlob,
                    0,
                    ref entropyBlob,
                    0,
                    0,
                    CryptProtectUiForbidden,
                    out outputBlob);
            if (!succeeded)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "Windows DPAPI could not transform the companion identity.");
            }

            return outputBlob.ToArray();
        }
        finally
        {
            inputBlob.ZeroAndFree();
            entropyBlob.ZeroAndFree();
            outputBlob.ZeroAndLocalFree();
        }
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows DPAPI is available only on Windows.");
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeBlob
    {
        public int Length;
        public nint Data;

        public static NativeBlob From(ReadOnlySpan<byte> bytes)
        {
            if (bytes.IsEmpty)
            {
                return default;
            }

            var pointer = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes.ToArray(), 0, pointer, bytes.Length);
            return new NativeBlob { Length = bytes.Length, Data = pointer };
        }

        public readonly byte[] ToArray()
        {
            if (Length <= 0 || Data == 0)
            {
                return [];
            }

            var result = new byte[Length];
            Marshal.Copy(Data, result, 0, Length);
            return result;
        }

        public void ZeroAndFree()
        {
            if (Data == 0)
            {
                return;
            }

            Marshal.Copy(new byte[Length], 0, Data, Length);
            Marshal.FreeHGlobal(Data);
            Data = 0;
            Length = 0;
        }

        public void ZeroAndLocalFree()
        {
            if (Data == 0)
            {
                return;
            }

            Marshal.Copy(new byte[Length], 0, Data, Length);
            _ = NativeMethods.LocalFree(Data);
            Data = 0;
            Length = 0;
        }
    }

    private static class NativeMethods
    {
        [DllImport("crypt32.dll", EntryPoint = "CryptProtectData", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptProtectData(
            ref NativeBlob input,
            string? description,
            ref NativeBlob optionalEntropy,
            nint reserved,
            nint prompt,
            uint flags,
            out NativeBlob output);

        [DllImport("crypt32.dll", EntryPoint = "CryptUnprotectData", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptUnprotectData(
            ref NativeBlob input,
            nint description,
            ref NativeBlob optionalEntropy,
            nint reserved,
            nint prompt,
            uint flags,
            out NativeBlob output);

        [DllImport("kernel32.dll", EntryPoint = "LocalFree", ExactSpelling = true)]
        internal static extern nint LocalFree(nint memory);
    }
}
