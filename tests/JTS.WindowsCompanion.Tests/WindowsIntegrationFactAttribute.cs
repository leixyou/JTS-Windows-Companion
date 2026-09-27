namespace JTS.WindowsCompanion.Tests;

[AttributeUsage(AttributeTargets.Method)]
public sealed class WindowsIntegrationFactAttribute : FactAttribute
{
    public WindowsIntegrationFactAttribute()
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10))
        {
            Skip = "Requires Windows 10 or Windows 11.";
        }
    }
}
