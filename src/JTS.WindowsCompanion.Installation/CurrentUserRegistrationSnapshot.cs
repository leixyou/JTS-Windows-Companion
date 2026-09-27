using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Win32;

namespace JTS.WindowsCompanion.Setup;

internal sealed record CurrentUserRegistrationSnapshot(
    int SchemaVersion,
    RegistryValueSnapshot? StartupValue,
    RegistryKeySnapshot? UninstallKey)
{
    public const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    public const string UninstallKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\JTSWindowsCompanion";
    public const string StartupValueName = "JTS Windows Companion";

    private const int CurrentSchemaVersion = 1;
    private const int MaximumSerializedCharacters = 256 * 1024;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = false,
        WriteIndented = false,
    };

    [SupportedOSPlatform("windows")]
    public static CurrentUserRegistrationSnapshot Capture()
    {
        using var runKey = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: false);
        var startupValue = runKey is not null && runKey.GetValueNames().Any(
            name => string.Equals(name, StartupValueName, StringComparison.OrdinalIgnoreCase))
                ? RegistryValueSnapshot.Capture(runKey, StartupValueName)
                : null;

        using var uninstallKey = Registry.CurrentUser.OpenSubKey(UninstallKeyPath, writable: false);
        var snapshot = new CurrentUserRegistrationSnapshot(
            CurrentSchemaVersion,
            startupValue,
            uninstallKey is null ? null : RegistryKeySnapshot.Capture(uninstallKey));
        snapshot.Validate();
        return snapshot;
    }

    public string Serialize()
    {
        Validate();
        var serialized = JsonSerializer.Serialize(this, JsonOptions);
        if (serialized.Length > MaximumSerializedCharacters)
        {
            throw new InvalidDataException("The current-user registration snapshot is too large.");
        }
        return serialized;
    }

    public static CurrentUserRegistrationSnapshot Deserialize(string serialized)
    {
        if (string.IsNullOrWhiteSpace(serialized) || serialized.Length > MaximumSerializedCharacters)
        {
            throw new InvalidDataException("The current-user registration snapshot has an invalid size.");
        }
        var snapshot = JsonSerializer.Deserialize<CurrentUserRegistrationSnapshot>(serialized, JsonOptions)
            ?? throw new InvalidDataException("The current-user registration snapshot is empty.");
        snapshot.Validate();
        return snapshot;
    }

    [SupportedOSPlatform("windows")]
    public void Restore()
    {
        if (StartupValue is null)
        {
            using var runKey = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true);
            runKey?.DeleteValue(StartupValueName, throwOnMissingValue: false);
        }
        else
        {
            using var runKey = Registry.CurrentUser.CreateSubKey(RunKeyPath, writable: true)
                ?? throw new UnauthorizedAccessException("The current-user startup registry key is unavailable.");
            StartupValue.WriteTo(runKey, StartupValueName);
        }

        Registry.CurrentUser.DeleteSubKeyTree(UninstallKeyPath, throwOnMissingSubKey: false);
        if (UninstallKey is not null)
        {
            using var uninstallKey = Registry.CurrentUser.CreateSubKey(UninstallKeyPath, writable: true)
                ?? throw new UnauthorizedAccessException("The current-user uninstall registry key is unavailable.");
            UninstallKey.WriteTo(uninstallKey);
        }
    }

    private void Validate()
    {
        if (SchemaVersion != CurrentSchemaVersion)
        {
            throw new InvalidDataException("The current-user registration snapshot schema is unsupported.");
        }
        var remainingEntries = 256;
        StartupValue?.Validate(ref remainingEntries);
        UninstallKey?.Validate(depth: 0, ref remainingEntries);
    }
}
