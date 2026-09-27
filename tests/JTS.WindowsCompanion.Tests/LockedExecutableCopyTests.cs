using JTS.WindowsCompanion.Setup;

namespace JTS.WindowsCompanion.Tests;

public sealed class LockedExecutableCopyTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("jts-setup-copy-").FullName;

    [Fact]
    public void Copy_PreservesExactBytesWithoutRequiringAuthenticode()
    {
        var source = Path.Combine(_directory, "downloaded-setup.exe");
        var destination = Path.Combine(_directory, InstallerLayout.SetupFileName);
        byte[] bytes = [0x4d, 0x5a, 0, 1, 2, 3, 255];
        File.WriteAllBytes(source, bytes);

        using var copy = LockedExecutableCopy.Create(source, destination);

        Assert.Equal(bytes, File.ReadAllBytes(destination));
        Assert.Equal(bytes, File.ReadAllBytes(source));
    }

    [Fact]
    public void Copy_RejectsExistingDestinationWithoutOverwritingIt()
    {
        var source = Path.Combine(_directory, "source.exe");
        var destination = Path.Combine(_directory, "existing.exe");
        File.WriteAllText(source, "new setup");
        File.WriteAllText(destination, "existing setup");

        Assert.Throws<IOException>(() => LockedExecutableCopy.Create(source, destination));
        Assert.Equal("existing setup", File.ReadAllText(destination));
    }

    [Fact]
    public void Copy_RejectsMissingSourceWithoutCreatingDestination()
    {
        var destination = Path.Combine(_directory, "copy.exe");

        Assert.Throws<FileNotFoundException>(() =>
            LockedExecutableCopy.Create(Path.Combine(_directory, "missing.exe"), destination));

        Assert.False(File.Exists(destination));
    }

    [WindowsIntegrationFact]
    public void Copy_HoldsBothFilesAgainstModificationUntilLaunchCompletes()
    {
        var source = Path.Combine(_directory, "source.exe");
        var destination = Path.Combine(_directory, "copy.exe");
        File.WriteAllText(source, "setup image");
        using (LockedExecutableCopy.Create(source, destination))
        {
            Assert.Throws<IOException>(() => File.WriteAllText(source, "replacement"));
            Assert.Throws<IOException>(() => File.WriteAllText(destination, "replacement"));
            Assert.Throws<IOException>(() => File.Delete(destination));
        }
        File.WriteAllText(destination, "unlocked after launch");
    }

    public void Dispose() => Directory.Delete(_directory, recursive: true);
}
