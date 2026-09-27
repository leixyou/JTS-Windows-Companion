using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace JTS.WindowsCompanion.UnattendedInstallation;

/// <summary>Ephemeral setup-only secret. Never converted to a managed string, persisted, or passed in argv.</summary>
internal sealed class AccountPassword : IDisposable
{
    internal const int CharacterCount = 48;
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+-.:;<=>?@[]^_{|}~";
    private IntPtr _pointer;

    private AccountPassword()
    {
        _pointer = Marshal.AllocHGlobal((CharacterCount + 1) * sizeof(char));
        try
        {
            for (var i = 0; i <= CharacterCount; i++) Marshal.WriteInt16(_pointer, i * sizeof(char), 0);
            // Guarantee four complexity classes; every remaining position is independently random.
            Write(0, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"); Write(1, "abcdefghijklmnopqrstuvwxyz");
            Write(2, "0123456789"); Write(3, "!#$%&()*+-.:;<=>?@[]^_{|}~");
            for (var i = 4; i < CharacterCount; i++) Write(i, Alphabet);
            for (var i = CharacterCount - 1; i > 0; i--)
            {
                var other = RandomNumberGenerator.GetInt32(i + 1);
                var value = Marshal.ReadInt16(_pointer, i * sizeof(char));
                Marshal.WriteInt16(_pointer, i * sizeof(char), Marshal.ReadInt16(_pointer, other * sizeof(char)));
                Marshal.WriteInt16(_pointer, other * sizeof(char), value);
            }
        }
        catch { Dispose(); throw; }
    }

    internal static AccountPassword Create() => new();
    // The single-threaded installation coordinator owns the lifetime through each native call.
    internal IntPtr Pointer => _pointer != IntPtr.Zero ? _pointer : throw new ObjectDisposedException(nameof(AccountPassword));
    private void Write(int offset, string alphabet) => Marshal.WriteInt16(_pointer, offset * sizeof(char),
        checked((short)alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)]));

    public void Dispose() { Clear(); GC.SuppressFinalize(this); }
    ~AccountPassword() => Clear();
    private void Clear()
    {
        var pointer = Interlocked.Exchange(ref _pointer, IntPtr.Zero);
        if (pointer == IntPtr.Zero) return;
        for (var i = 0; i <= CharacterCount; i++) Marshal.WriteInt16(pointer, i * sizeof(char), 0);
        Marshal.FreeHGlobal(pointer);
    }
}
