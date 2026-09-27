using Xunit;

namespace JTS.WindowsCompanion.UnattendedInstallation.Tests;

public sealed class InstallationPayloadPlanTests
{
    private static string[] Files => [.. InstallationPayload.Names, InstallationPayloadPlan.SetupName, "e_sqlite3.dll"];
    [Fact]
    public void InstallsAuthenticatedAdjacentNativeCodeButNotUi()
    {
        var plan = InstallationPayloadPlan.SelectFiles(2, Files);
        Assert.Equal(4, plan.Length); Assert.Contains("e_sqlite3.dll", plan);
        Assert.DoesNotContain(InstallationPayloadPlan.SetupName, plan);
    }
    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(3)]
    public void OtherSchemasRefusedForNewInstaller(int schema)
        => Assert.Throws<UnattendedInstallationException>(() => InstallationPayloadPlan.SelectFiles(schema, Files));
    [Theory]
    [InlineData("e_sqlite3.dll")]
    [InlineData("JTS.WindowsCompanion.WorkerRunner.exe")]
    [InlineData("JTS.WindowsCompanion.UnattendedSetup.exe")]
    public void MissingRequiredPayloadFails(string omitted)
        => Assert.Throws<UnattendedInstallationException>(() => InstallationPayloadPlan.SelectFiles(2, Files.Where(n => n != omitted).ToArray()));
    [Theory]
    [InlineData("other.exe")] [InlineData("payload.json")] [InlineData("../extra.dll")]
    [InlineData("sub\\extra.dll")] [InlineData("extra:stream.dll")] [InlineData("E_SQLITE3.dll")]
    public void UnapprovedOrDuplicateEntriesRejected(string extra)
        => Assert.Throws<UnattendedInstallationException>(() => InstallationPayloadPlan.SelectFiles(2, [.. Files, extra]));
    [Fact]
    public void AdditionalAuthenticatedNativeLibrariesAreIncluded()
    {
        var plan = InstallationPayloadPlan.SelectFiles(2, [.. Files, "coreclr.dll", "clrjit.dll"]);
        Assert.Equal(6, plan.Length); Assert.Contains("coreclr.dll", plan); Assert.Contains("clrjit.dll", plan);
    }
}
