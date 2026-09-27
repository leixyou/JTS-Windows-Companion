using JTS.WindowsCompanion.Setup;

namespace JTS.WindowsCompanion.Tests;

public sealed class InstallerTests
{
    [Fact]
    public void Options_DefaultToInteractiveInstall()
    {
        var options = InstallerOptions.Parse([]);

        Assert.Equal(InstallerAction.Install, options.Action);
        Assert.False(options.Quiet);
        Assert.False(options.PurgeData);
    }

    [Fact]
    public void Options_ParseQuietPurgeUninstall()
    {
        var options = InstallerOptions.Parse(["--quiet", "--uninstall", "--purge-data"]);

        Assert.Equal(InstallerAction.Uninstall, options.Action);
        Assert.True(options.Quiet);
        Assert.True(options.PurgeData);
    }

    [Fact]
    public void Options_ParseInternalInstall()
    {
        var options = InstallerOptions.Parse(["--install-internal", "--quiet"]);

        Assert.Equal(InstallerAction.InstallInternal, options.Action);
        Assert.True(options.Quiet);
        Assert.False(options.PurgeData);
    }

    [Theory]
    [InlineData("--install", "--uninstall")]
    [InlineData("--repair", "--uninstall-internal")]
    [InlineData("--install", "--install-internal")]
    [InlineData("--purge-data", "--repair")]
    [InlineData("--unknown", "--quiet")]
    public void Options_RejectConflictingOrInvalidArguments(string first, string second)
    {
        Assert.Throws<ArgumentException>(() => InstallerOptions.Parse([first, second]));
    }

    [Fact]
    public void Options_RequirePinnedExplicitDelegationAndSupportExactOfflineRevocation()
    {
        var digest = new string('A', 64);
        var path = Path.Combine(Path.GetTempPath(), "delegation.json");
        var parsed = InstallerOptions.Parse(["--install", "--quiet", "--delegated-enrollment", path, "--delegated-enrollment-sha256", digest]);
        Assert.Equal(path, parsed.DelegatedEnrollmentPath);
        Assert.Equal(digest, parsed.DelegatedEnrollmentSha256);
        var id = Guid.NewGuid();
        var revoke = InstallerOptions.Parse(["--quiet", "--revoke-delegation", id.ToString("D")]);
        Assert.Equal(InstallerAction.RevokeDelegation, revoke.Action);
        Assert.Equal(id, revoke.RevokeDelegationGrantId);
        foreach (var invalid in new string[][]
        {
            ["--delegated-enrollment", path], ["--delegated-enrollment-sha256", digest],
            ["--uninstall", "--delegated-enrollment", path, "--delegated-enrollment-sha256", digest],
            ["--delegated-enrollment", path, "--delegated-enrollment", path],
            ["--delegated-enrollment-sha256", "invalid"], ["--revoke-delegation", Guid.Empty.ToString()],
            ["--revoke-delegation", id.ToString(), "--install"],
            ["--revoke-delegation", id.ToString(), "--purge-data"],
        }) Assert.Throws<ArgumentException>(() => InstallerOptions.Parse(invalid));
    }

    [Theory]
    [InlineData("", "\"\"")]
    [InlineData("plain", "\"plain\"")]
    [InlineData("two words", "\"two words\"")]
    [InlineData("documents=D:\\", "\"documents=D:\\\\\"")]
    [InlineData("a\"b", "\"a\\\"b\"")]
    public void WindowsArgumentQuoter_PreservesWindowsParsingBoundaries(string value, string expected)
    {
        Assert.Equal(expected, WindowsCommandLineArgumentQuoter.Quote(value));
    }

    [Fact]
    public void SafeInstallRoot_RejectsSiblingPrefixAndParentEscape()
    {
        var localRoot = Path.Combine(Path.GetTempPath(), $"jts-local-{Guid.NewGuid():N}");
        var safeChild = Path.Combine(localRoot, "Programs", "JTS Terminal");
        var siblingPrefix = localRoot + "-outside";

        InstallerLayout.EnsureSafeInstallRoot(localRoot, safeChild);
        Assert.Throws<UnauthorizedAccessException>(
            () => InstallerLayout.EnsureSafeInstallRoot(localRoot, siblingPrefix));
        Assert.Throws<UnauthorizedAccessException>(
            () => InstallerLayout.EnsureSafeInstallRoot(localRoot, Path.Combine(localRoot, "..", "outside")));
    }

    [Fact]
    public void DeleteDirectory_RemovesOnlyTheRequestedTree()
    {
        var parent = Path.Combine(Path.GetTempPath(), $"jts-delete-{Guid.NewGuid():N}");
        var requested = Path.Combine(parent, "requested");
        var retained = Path.Combine(parent, "retained");
        try
        {
            Directory.CreateDirectory(Path.Combine(requested, "nested"));
            Directory.CreateDirectory(retained);
            File.WriteAllText(Path.Combine(requested, "nested", "payload.bin"), "payload");
            File.WriteAllText(Path.Combine(retained, "identity.v1.json"), "identity");

            InstallerLayout.DeleteDirectoryWithoutFollowingLinks(requested);

            Assert.False(Directory.Exists(requested));
            Assert.True(File.Exists(Path.Combine(retained, "identity.v1.json")));
        }
        finally
        {
            if (Directory.Exists(parent))
            {
                Directory.Delete(parent, recursive: true);
            }
        }
    }
}
