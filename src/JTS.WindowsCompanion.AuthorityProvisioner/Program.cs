namespace JTS.WindowsCompanion.AuthorityProvisioner;

internal static class Program
{
    private static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10)
            || System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture != System.Runtime.InteropServices.Architecture.X64)
        { Console.Error.WriteLine("PROVISION_WINDOWS_REQUIRED"); return 10; }
        try
        {
            var enrollment = ProvisioningIntent.ParseArguments(args);
            WindowsAuthorityProvisioning.Run(enrollment);
            Console.WriteLine("AUTHORITY_STATE_STAGED_NOT_ENABLED");
            return 0;
        }
        catch (ProvisioningException error) { Console.Error.WriteLine(error.Code); return 11; }
        catch { Console.Error.WriteLine("AUTHORITY_PROVISIONING_FAILED"); return 70; }
    }
}
