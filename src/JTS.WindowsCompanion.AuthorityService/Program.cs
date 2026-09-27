using JTS.WindowsCompanion.AuthorityService;

// No config path, credentials, scripts, trust key or provisioning switch is accepted from argv.
if (!OperatingSystem.IsWindowsVersionAtLeast(10) || !Environment.Is64BitProcess)
{ Console.Error.WriteLine("AUTHORITY_WINDOWS_REQUIRED"); return 10; }
if (args is not ["--service"])
{ Console.Error.WriteLine("AUTHORITY_SERVICE_ONLY"); return 11; }
try { return WindowsAuthorityServiceHost.Run(); }
catch { Console.Error.WriteLine("AUTHORITY_SERVICE_FAILED"); return 70; }
