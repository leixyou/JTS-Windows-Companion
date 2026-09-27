using Xunit;

namespace JTS.WindowsCompanion.Execution.Tests;

public sealed class WorkerWorkingDirectoryTests
{
    [Fact]
    public void MissingSharedRootNeverFallsBackToProgramOrCurrentDirectory()
    {
        var directory = Directory.CreateTempSubdirectory("jts-worker-cwd-");
        try { Assert.Throws<InvalidOperationException>(() => WorkerWorkingDirectory.Resolve(".", directory.FullName)); }
        finally { directory.Delete(); }
    }
    [Fact]
    public void ExplicitAbsoluteWorkingDirectoryIsPreservedForNativeValidation()
        => Assert.Equal(@"C:\Work", WorkerWorkingDirectory.Resolve(@"C:\Work", @"C:\ProgramData"));
}
