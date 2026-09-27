using System.Runtime.InteropServices;
using JTS.WindowsCompanion.Enrollment;
using JTS.WindowsCompanion.UnattendedInstallation;

namespace JTS.WindowsCompanion.UnattendedSetup;

internal static class Program
{
    [STAThread]
    private static int Main(string[] arguments)
    {
        SetupEntryMode mode;
        try { mode = SetupEntryArguments.Parse(arguments); }
        catch (ArgumentException) { Console.Error.WriteLine("SETUP_ARGUMENTS_REJECTED"); return 2; }
        var cli = mode is SetupEntryMode.Status or SetupEntryMode.EnrollStandardInput;
        if (!Environment.UserInteractive || RuntimeInformation.ProcessArchitecture != Architecture.X64) return 3;
        try
        {
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.ThrowException);
            ApplicationConfiguration.Initialize();
            using var bundle = SetupBundle.OpenCurrent();
            if (mode == SetupEntryMode.DelegatedInstallation) return DelegatedSetup.Run(arguments, bundle.Directory);
            if (cli) return EnrollmentCommand.RunAsync(mode, bundle.Directory).GetAwaiter().GetResult();
            using var form = new SetupForm(bundle.Directory, WindowsInstallationPresence.Inspect());
            Application.Run(form);
            return form.ExitCode;
        }
        catch (Exception error)
        {
            if (cli)
            {
                Console.Error.WriteLine(error is EnrollmentException enrollment
                    ? EnrollmentCommand.SafeErrorCode(enrollment.Code) : "SETUP_OPERATION_FAILED");
            }
            else
            {
                // Never expose exception messages, paths, environment data or nested errors to this elevated UI.
                MessageBox.Show("The connection manager could not be opened safely. Keep the complete, unmodified release bundle together and check the local service. No automatic repair was attempted.",
                    SetupText.Title, MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            return 1;
        }
    }
}
