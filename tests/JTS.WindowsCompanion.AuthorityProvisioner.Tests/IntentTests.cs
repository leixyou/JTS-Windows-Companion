using System.Text;
using System.Text.Json.Nodes;
using Xunit;

namespace JTS.WindowsCompanion.AuthorityProvisioner.Tests;

public sealed class IntentTests
{
    [Fact]
    public void ExactInstallerIntentAndOnlyPublicArgumentsAreAccepted()
    {
        using var f = new ProvisioningFixture();
        Assert.Equal(f.Intent, ProvisioningIntent.Parse(f.IntentBytes(), f.Enrollment, ProvisioningFixture.Authority, f.Clock));
        Assert.Equal(f.Enrollment, ProvisioningIntent.ParseArguments(["--provision", f.Enrollment.ToString("D")]));
    }
    [Theory]
    [InlineData("operation", "repair")]
    [InlineData("authoritySid", "S-1-5-18")]
    [InlineData("authoritySid", "S-1-5-21-1-2-3-1102")]
    [InlineData("workerSid", "S-1-5-21-1-2-3-1100")]
    [InlineData("workerSid", "S-1-5-21-01-2-3-1101")]
    [InlineData("workerSid", "S-1-5-21-1-2-3-500")]
    [InlineData("workerSid", "S-1-5-21-1-2-3-4294967296")]
    [InlineData("enrollmentId", "00000000-0000-0000-0000-000000000000")]
    [InlineData("enrollmentId", "10000000-0000-0000-0000-000000000000")]
    [InlineData("createdAt", "2026-09-19T00:00:01.0000000+00:00")]
    [InlineData("expiresAt", "2026-09-19T00:00:00.0000000+00:00")]
    [InlineData("expiresAt", "2026-09-19T01:00:00.0000000+00:00")]
    [InlineData("expiresAt", "2026-09-19T08:20:00.0000000+08:00")]
    [InlineData("password", "never-accepted")]
    public void ContextAndSchemaAreStrict(string key, string value)
    {
        using var f = new ProvisioningFixture(); var json = JsonNode.Parse(f.IntentBytes())!; json[key] = value;
        Assert.Throws<ProvisioningException>(() => ProvisioningIntent.Parse(Encoding.UTF8.GetBytes(json.ToJsonString()), f.Enrollment, ProvisioningFixture.Authority, f.Clock));
    }
    [Fact]
    public void MissingDuplicateOversizedMalformedAndWrongTypeAreRejected()
    {
        using var f = new ProvisioningFixture(); var original = Encoding.UTF8.GetString(f.IntentBytes());
        var missing = JsonNode.Parse(original)!; missing.AsObject().Remove("workerSid");
        var wrong = JsonNode.Parse(original)!; wrong["schemaVersion"] = "1";
        foreach (var json in new[] { missing.ToJsonString(), wrong.ToJsonString(), "[]", "null", "{", original.Replace("{", "{\"schemaVersion\":1,", StringComparison.Ordinal) })
            Assert.Throws<ProvisioningException>(() => ProvisioningIntent.Parse(Encoding.UTF8.GetBytes(json), f.Enrollment, ProvisioningFixture.Authority, f.Clock));
        foreach (var bytes in new byte[][] { [], new byte[4097], [0xff] })
            Assert.Throws<ProvisioningException>(() => ProvisioningIntent.Parse(bytes, f.Enrollment, ProvisioningFixture.Authority, f.Clock));
    }
    [Fact]
    public void CliNeverAcceptsCredentialsPathsOrAlternateModes()
    {
        using var f = new ProvisioningFixture(); var id = f.Enrollment.ToString("D");
        foreach (var args in new string[][] { [], ["--service"], ["--provision", id, "--password", "secret"], ["--provision", "../state"],
            ["--provision", "00000000-0000-0000-0000-000000000000"], ["--provision", "AAAAAAAA-0000-0000-0000-000000000001"], ["--repair", id] })
            Assert.Throws<ProvisioningException>(() => ProvisioningIntent.ParseArguments(args));
    }
}
