using System.Runtime.InteropServices;

namespace JTS.WindowsCompanion.Setup;

internal static class SetupUserInterface
{
    private const uint Ok = 0x00000000;
    private const uint YesNo = 0x00000004;
    private const uint IconError = 0x00000010;
    private const uint IconQuestion = 0x00000020;
    private const uint IconInformation = 0x00000040;
    private const int Yes = 6;

    public static void ShowSuccess(string message) =>
        _ = MessageBox(IntPtr.Zero, message, "JTS Windows Companion", Ok | IconInformation);

    public static void ShowError(string message) =>
        _ = MessageBox(IntPtr.Zero, message, "JTS Windows Companion Setup", Ok | IconError);

    public static bool Confirm(string message) =>
        MessageBox(IntPtr.Zero, message, "JTS Windows Companion Setup", YesNo | IconQuestion) == Yes;

    [DllImport("user32.dll", EntryPoint = "MessageBoxW", CharSet = CharSet.Unicode)]
    private static extern int MessageBox(
        IntPtr windowHandle,
        string text,
        string caption,
        uint type);
}
