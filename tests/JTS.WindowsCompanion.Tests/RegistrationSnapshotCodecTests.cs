using JTS.WindowsCompanion.Setup;

namespace JTS.WindowsCompanion.Tests;

public sealed class RegistrationSnapshotCodecTests
{
    [Fact]
    public void Codec_RoundTripsAllSupportedRegistryValueKinds()
    {
        var snapshot = new CurrentUserRegistrationSnapshot(
            1,
            new RegistryValueSnapshot(
                CurrentUserRegistrationSnapshot.StartupValueName,
                InstallerRegistryValueKind.ExpandString,
                "%LOCALAPPDATA%\\agent.exe",
                null,
                null,
                null,
                null),
            new RegistryKeySnapshot(
                [
                    new RegistryValueSnapshot("String", InstallerRegistryValueKind.String, "value", null, null, null, null),
                    new RegistryValueSnapshot("DWord", InstallerRegistryValueKind.DWord, null, 42, null, null, null),
                    new RegistryValueSnapshot("QWord", InstallerRegistryValueKind.QWord, null, null, 9_000_000_000, null, null),
                    new RegistryValueSnapshot("Multi", InstallerRegistryValueKind.MultiString, null, null, null, ["one", "two"], null),
                    new RegistryValueSnapshot("Binary", InstallerRegistryValueKind.Binary, null, null, null, null, "AAEC/w=="),
                    new RegistryValueSnapshot("None", InstallerRegistryValueKind.None, null, null, null, null, "AwQ="),
                ],
                [
                    new RegistrySubKeySnapshot(
                        "Nested",
                        new RegistryKeySnapshot(
                            [new RegistryValueSnapshot("", InstallerRegistryValueKind.String, "default", null, null, null, null)],
                            [])),
                ]));

        var serialized = snapshot.Serialize();
        var restored = CurrentUserRegistrationSnapshot.Deserialize(serialized);

        Assert.Equal(serialized, restored.Serialize());
    }

    [Fact]
    public void Codec_RejectsUnsupportedSchemaAndInvalidBinary()
    {
        var unsupported = new CurrentUserRegistrationSnapshot(2, null, null);
        var invalidBinary = new CurrentUserRegistrationSnapshot(
            1,
            new RegistryValueSnapshot("value", InstallerRegistryValueKind.Binary, null, null, null, null, "not-base64"),
            null);

        Assert.Throws<InvalidDataException>(unsupported.Serialize);
        Assert.Throws<InvalidDataException>(invalidBinary.Serialize);
    }
}
