using System.Runtime.Versioning;
using Microsoft.Win32;

namespace JTS.WindowsCompanion.Setup;

internal sealed record RegistryKeySnapshot(
    IReadOnlyList<RegistryValueSnapshot> Values,
    IReadOnlyList<RegistrySubKeySnapshot> SubKeys)
{
    [SupportedOSPlatform("windows")]
    public static RegistryKeySnapshot Capture(RegistryKey key)
    {
        var remainingEntries = 256;
        return Capture(key, depth: 0, ref remainingEntries);
    }

    [SupportedOSPlatform("windows")]
    private static RegistryKeySnapshot Capture(RegistryKey key, int depth, ref int remainingEntries)
    {
        if (depth > 8)
        {
            throw new InvalidDataException("The current-user registration tree is too deep to snapshot safely.");
        }
        var valueNames = key.GetValueNames();
        var subKeyNames = key.GetSubKeyNames();
        if (valueNames.Length + subKeyNames.Length > remainingEntries)
        {
            throw new InvalidDataException("The current-user registration tree is too large to snapshot safely.");
        }
        remainingEntries -= valueNames.Length + subKeyNames.Length;

        var values = valueNames
            .Select(name => RegistryValueSnapshot.Capture(key, name))
            .ToArray();
        var subKeys = new List<RegistrySubKeySnapshot>();
        foreach (var name in subKeyNames)
        {
            using var subKey = key.OpenSubKey(name, writable: false)
                ?? throw new IOException("A current-user registration subkey disappeared while setup was taking a snapshot.");
            subKeys.Add(new RegistrySubKeySnapshot(
                name,
                Capture(subKey, depth + 1, ref remainingEntries)));
        }
        return new RegistryKeySnapshot(values, subKeys);
    }

    [SupportedOSPlatform("windows")]
    public void WriteTo(RegistryKey key)
    {
        foreach (var value in Values)
        {
            value.WriteTo(key, value.Name);
        }
        foreach (var subKey in SubKeys)
        {
            using var destination = key.CreateSubKey(subKey.Name, writable: true)
                ?? throw new UnauthorizedAccessException("A current-user registration subkey could not be restored.");
            subKey.Key.WriteTo(destination);
        }
    }

    public void Validate(int depth, ref int remainingEntries)
    {
        if (depth > 8 || Values is null || SubKeys is null)
        {
            throw new InvalidDataException("The current-user registration snapshot tree is invalid.");
        }
        foreach (var value in Values)
        {
            if (value is null)
            {
                throw new InvalidDataException("A current-user registration snapshot value is missing.");
            }
            value.Validate(ref remainingEntries);
        }
        foreach (var subKey in SubKeys)
        {
            if (subKey is null || subKey.Key is null ||
                --remainingEntries < 0 ||
                string.IsNullOrWhiteSpace(subKey.Name) ||
                subKey.Name.Length > 255 ||
                subKey.Name.Contains('\\', StringComparison.Ordinal))
            {
                throw new InvalidDataException("A current-user registration snapshot subkey is invalid.");
            }
            subKey.Key.Validate(depth + 1, ref remainingEntries);
        }
    }
}

internal sealed record RegistrySubKeySnapshot(string Name, RegistryKeySnapshot Key);

internal enum InstallerRegistryValueKind
{
    String = 1,
    ExpandString = 2,
    Binary = 3,
    DWord = 4,
    MultiString = 7,
    QWord = 11,
    None = -1,
}

internal sealed record RegistryValueSnapshot(
    string Name,
    InstallerRegistryValueKind Kind,
    string? Text,
    int? DWord,
    long? QWord,
    IReadOnlyList<string>? MultiString,
    string? BinaryBase64)
{
    [SupportedOSPlatform("windows")]
    public static RegistryValueSnapshot Capture(RegistryKey key, string name)
    {
        var kind = key.GetValueKind(name);
        var value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames)
            ?? throw new InvalidDataException("A current-user registration value disappeared while setup was taking a snapshot.");
        return kind switch
        {
            RegistryValueKind.String or RegistryValueKind.ExpandString =>
                new(name, ConvertKind(kind), (string)value, null, null, null, null),
            RegistryValueKind.DWord =>
                new(name, InstallerRegistryValueKind.DWord, null, Convert.ToInt32(value), null, null, null),
            RegistryValueKind.QWord =>
                new(name, InstallerRegistryValueKind.QWord, null, null, Convert.ToInt64(value), null, null),
            RegistryValueKind.MultiString =>
                new(name, InstallerRegistryValueKind.MultiString, null, null, null, (string[])value, null),
            RegistryValueKind.Binary or RegistryValueKind.None =>
                new(name, ConvertKind(kind), null, null, null, null, Convert.ToBase64String((byte[])value)),
            _ => throw new InvalidDataException("A current-user registration value has an unsupported type."),
        };
    }

    [SupportedOSPlatform("windows")]
    public void WriteTo(RegistryKey key, string destinationName) =>
        key.SetValue(destinationName, Materialize(), (RegistryValueKind)(int)Kind);

    public void Validate(ref int remainingEntries)
    {
        if (--remainingEntries < 0 || Name is null || Name.Length > 16 * 1024)
        {
            throw new InvalidDataException("A current-user registration snapshot value is invalid.");
        }
        _ = Materialize();
    }

    private object Materialize()
    {
        return Kind switch
        {
            InstallerRegistryValueKind.String or InstallerRegistryValueKind.ExpandString
                when Text is not null && Text.Length <= 64 * 1024 &&
                     DWord is null && QWord is null && MultiString is null && BinaryBase64 is null => Text,
            InstallerRegistryValueKind.DWord
                when Text is null && DWord.HasValue && QWord is null &&
                     MultiString is null && BinaryBase64 is null => DWord.Value,
            InstallerRegistryValueKind.QWord
                when Text is null && DWord is null && QWord.HasValue &&
                     MultiString is null && BinaryBase64 is null => QWord.Value,
            InstallerRegistryValueKind.MultiString
                when Text is null && DWord is null && QWord is null &&
                     MultiString is not null && BinaryBase64 is null &&
                     MultiString.Count <= 256 &&
                     MultiString.All(value => value is not null && value.Length <= 64 * 1024) =>
                MultiString.ToArray(),
            InstallerRegistryValueKind.Binary or InstallerRegistryValueKind.None
                when Text is null && DWord is null && QWord is null &&
                     MultiString is null && BinaryBase64 is not null && BinaryBase64.Length <= 128 * 1024 =>
                DecodeBinary(BinaryBase64),
            _ => throw new InvalidDataException("A current-user registration snapshot value payload is invalid."),
        };
    }

    [SupportedOSPlatform("windows")]
    private static InstallerRegistryValueKind ConvertKind(RegistryValueKind kind) =>
        (InstallerRegistryValueKind)(int)kind;

    private static byte[] DecodeBinary(string base64)
    {
        try
        {
            return Convert.FromBase64String(base64);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("A current-user registration binary value is not valid base64.", exception);
        }
    }
}
