using System.Security.Cryptography;
using JTS.WindowsCompanion.Files;
using JTS.WindowsCompanion.Managed;
using JTS.WindowsCompanion.Shell;

namespace JTS.WindowsCompanion.Tests;

public sealed class PolicyTests
{
    [Fact]
    public void ShellDefaultDirectoryResolvesOnlyTheSelectedConfiguredRoot()
    {
        using var documents = new TemporaryDirectory();
        using var desktop = new TemporaryDirectory();
        var sandbox = new FileSandbox([
            new FileRoot("documents", documents.Path), new FileRoot("desktop", desktop.Path)]);
        var policy = new CurrentUserShellPolicy(sandbox);
        var baseline = new ShellExecutionRequest("Get-Location", "documents", ".");
        Assert.Equal(documents.Path, policy.Validate(baseline).FullPath);
        Assert.Equal(desktop.Path, policy.Validate(baseline with { RootId = "desktop" }).FullPath);
        Assert.Equal("ROOT_NOT_ALLOWED", Assert.Throws<FileSandboxException>(() =>
            policy.Validate(baseline with { RootId = "unconfigured" })).Code);
        Assert.Equal("PATH_TRAVERSAL", Assert.Throws<FileSandboxException>(() =>
            sandbox.Resolve("documents", ".", allowMissingLeaf: true)).Code);
        Assert.Throws<UnauthorizedAccessException>(() => policy.Validate(baseline with { RequiresElevation = true }));
    }

    [Theory]
    [InlineData("./")]
    [InlineData(".\\")]
    [InlineData("./work")]
    [InlineData("work/.")]
    [InlineData("work/../work")]
    [InlineData("work\\..\\work")]
    [InlineData("../outside")]
    [InlineData("..")]
    public void ShellDefaultDirectoryDoesNotAdmitNestedTraversal(string path)
    {
        using var temporary = new TemporaryDirectory();
        Directory.CreateDirectory(Path.Combine(temporary.Path, "work"));
        var policy = new CurrentUserShellPolicy(new FileSandbox([new FileRoot("documents", temporary.Path)]));
        var exception = Assert.Throws<FileSandboxException>(() =>
            policy.Validate(new ShellExecutionRequest("Get-Location", "documents", path)));
        Assert.Equal("PATH_TRAVERSAL", exception.Code);
    }

    [Fact]
    public void ShellDefaultDirectoryRechecksRootReplacementAndRemoval()
    {
        using var parent = new TemporaryDirectory();
        using var outside = new TemporaryDirectory();
        var root = Path.Combine(parent.Path, "configured");
        Directory.CreateDirectory(root);
        var policy = new CurrentUserShellPolicy(new FileSandbox([new FileRoot("documents", root)]));
        var request = new ShellExecutionRequest("Get-Location", "documents", ".");
        Assert.Equal(root, policy.Validate(request).FullPath);
        Directory.Delete(root);
        Assert.Equal("PATH_NOT_FOUND", Assert.Throws<FileSandboxException>(() => policy.Validate(request)).Code);
        Directory.CreateSymbolicLink(root, outside.Path);
        try
        {
            Assert.Equal("REPARSE_POINT_REJECTED", Assert.Throws<FileSandboxException>(() => policy.Validate(request)).Code);
        }
        finally { Directory.Delete(root); }
    }

    [Fact]
    public void ShellPolicy_RejectsElevationSecretEnvironmentAndEscapes()
    {
        using var temporary = new TemporaryDirectory();
        Directory.CreateDirectory(Path.Combine(temporary.Path, "work"));
        var policy = new CurrentUserShellPolicy(new FileSandbox([new FileRoot("workspace", temporary.Path)]));
        var baseline = new ShellExecutionRequest("Get-ChildItem", "workspace", "work");

        Assert.EndsWith("work", policy.Validate(baseline).FullPath, StringComparison.Ordinal);
        Assert.Throws<UnauthorizedAccessException>(() => policy.Validate(baseline with { RequiresElevation = true }));
        Assert.Throws<ArgumentException>(() => policy.Validate(baseline with
        {
            Environment = new Dictionary<string, string> { ["API_TOKEN"] = "redacted" },
        }));
        Assert.Throws<FileSandboxException>(() => policy.Validate(baseline with { WorkingDirectory = "../outside" }));
    }

    [Fact]
    public void ManagedPolicy_AuthorizesOnlyManifestedFixedOperations()
    {
        var manifest = new WindowsTaskProviderManifest(
            "vrc-factory",
            "1.0.0",
            Convert.ToHexString(RandomNumberGenerator.GetBytes(32)),
            [new ManagedOperationDefinition(
                "clean-install-auto",
                new HashSet<string>(["jobId", "packagePath"], StringComparer.Ordinal),
                new HashSet<string>(["factory"], StringComparer.Ordinal),
                TimeSpan.FromMinutes(30))]);
        var policy = new ManagedServicePolicy([manifest]);
        var request = new ManagedOperationRequest(
            "vrc-factory",
            "clean-install-auto",
            new Dictionary<string, string>
            {
                ["jobId"] = "avatar-pilot-001",
                ["packagePath"] = "jobs/avatar-pilot-001.zip",
            },
            new HashSet<string>(["factory"], StringComparer.Ordinal),
            TimeSpan.FromMinutes(20));

        var authorized = policy.Authorize(request);
        Assert.Equal("clean-install-auto", authorized.OperationId);
        Assert.Throws<UnauthorizedAccessException>(() => policy.Authorize(request with
        {
            Arguments = new Dictionary<string, string>(request.Arguments) { ["script"] = "whoami" },
        }));
        Assert.Throws<UnauthorizedAccessException>(() => policy.Authorize(request with
        {
            Arguments = new Dictionary<string, string>(request.Arguments)
            {
                ["packagePath"] = "../outside.zip",
            },
        }));
        Assert.Throws<UnauthorizedAccessException>(() => policy.Authorize(request with
        {
            Arguments = new Dictionary<string, string>(request.Arguments)
            {
                ["packagePath"] = "C:\\outside.zip",
            },
        }));
        Assert.Throws<UnauthorizedAccessException>(() => policy.Authorize(request with { OperationId = "shell.exec" }));
    }

    [Fact]
    public void ManagedPolicy_RejectsShellOperationsAtInstallationTime()
    {
        var manifest = new WindowsTaskProviderManifest(
            "unsafe",
            "1.0.0",
            new string('A', 64),
            [new ManagedOperationDefinition(
                "powershell.exec",
                new HashSet<string>(),
                new HashSet<string>(),
                TimeSpan.FromMinutes(1))]);

        Assert.Throws<ArgumentException>(() => new ManagedServicePolicy([manifest]));
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"jts-companion-policy-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
