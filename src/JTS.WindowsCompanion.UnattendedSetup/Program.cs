using System.Runtime.InteropServices;

namespace JTS.WindowsCompanion.UnattendedSetup;

internal static class Program
{
    [STAThread]
    private static int Main(string[] arguments)
    {
        if (!Environment.UserInteractive || RuntimeInformation.ProcessArchitecture != Architecture.X64)
            return 3;
        try
        {
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.ThrowException);
            ApplicationConfiguration.Initialize();
            using var bundle = SetupBundle.OpenCurrent();
            if (arguments.Length != 0) return DelegatedSetup.Run(arguments, bundle.Directory);
            using var form = new SetupForm(bundle.Directory);
            Application.Run(form);
            return form.ExitCode;
        }
        catch
        {
            // Never expose exception messages, paths, environment data or nested errors to this elevated UI.
            MessageBox.Show("Setup could not be opened safely. Keep the complete, unmodified release bundle together and contact support. No automatic repair was attempted.",
                SetupText.Title, MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }
}
