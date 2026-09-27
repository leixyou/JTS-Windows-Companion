using System.Text;
using System.Text.Json.Nodes;
using Xunit;

namespace JTS.WindowsCompanion.AuthorityService.Tests;

public sealed class ConfigurationTests
{
    internal const string Json = """
        {"schemaVersion":1,"enabled":true,"enrollmentId":"11111111-2222-3333-4444-555555555555",
         "deviceId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
         "authoritySid":"S-1-5-21-111-222-333-1001","relayOrigin":"https://relay.example:8443/",
         "worker":{"accountName":".\\JTSWorker25","accountSid":"S-1-5-21-111-222-333-1002",
                   "executablePath":"C:\\Program Files\\JTS Terminal\\JTS.WindowsCompanion.WorkerRunner.exe"}}
        """;
    [Fact]
    public void ExplicitCompleteConfigurationParsesWithoutCreatingAnything()
    {
        var config = Parse(Json);
        Assert.Equal("relay.example", config.RelayOrigin.Host); Assert.Equal(8443, config.RelayOrigin.Port);
        Assert.NotEqual(config.AuthoritySid, config.Worker.AccountSid);
        Assert.Equal("JTSCompanionAuthority25", AuthorityConfiguration.ServiceName);
    }
    [Theory]
    [InlineData("http://relay.example/")]
    [InlineData("http://127.0.0.1/")]
    [InlineData("https://user:password@relay.example/")]
    [InlineData("https://relay.example/path")]
    [InlineData("https://relay.example/?token=secret")]
    [InlineData("https://relay.example/#part")]
    [InlineData("file:///tmp/relay")]
    [InlineData("/relative")]
    public void UnsafeOrNonOriginRelayLocationsAreRejected(string origin)
    {
        var json = JsonNode.Parse(Json)!; json["relayOrigin"] = origin;
        Assert.Throws<AuthorityException>(() => Parse(json.ToJsonString()));
    }
    [Theory]
    [InlineData("version")]
    [InlineData("disabled")]
    [InlineData("empty-id")]
    [InlineData("bad-id")]
    [InlineData("device")]
    [InlineData("authority-builtin")]
    [InlineData("same-account")]
    [InlineData("unknown")]
    [InlineData("worker-unknown")]
    [InlineData("missing")]
    [InlineData("worker-unc")]
    [InlineData("worker-builtin")]
    [InlineData("worker-other-exe")]
    public void IncompleteDisabledOrExpandedPolicyIsRejected(string kind)
    {
        var json = JsonNode.Parse(Json)!;
        switch (kind)
        {
            case "version": json["schemaVersion"] = 2; break;
            case "disabled": json["enabled"] = false; break;
            case "empty-id": json["enrollmentId"] = Guid.Empty.ToString("D"); break;
            case "bad-id": json["enrollmentId"] = "abc"; break;
            case "device": json["deviceId"] = new string('A', 64); break;
            case "authority-builtin": json["authoritySid"] = "S-1-5-18"; break;
            case "same-account": json["worker"]!["accountSid"] = json["authoritySid"]!.GetValue<string>(); break;
            case "unknown": json["ignoreTlsErrors"] = true; break;
            case "worker-unknown": json["worker"]!["password"] = "not-accepted"; break;
            case "missing": json.AsObject().Remove("deviceId"); break;
            case "worker-unc": json["worker"]!["executablePath"] = @"\\server\share\JTS.WindowsCompanion.WorkerRunner.exe"; break;
            case "worker-builtin": json["worker"]!["accountSid"] = "S-1-5-20"; break;
            case "worker-other-exe": json["worker"]!["executablePath"] = @"C:\Windows\System32\cmd.exe"; break;
        }
        Assert.Throws<AuthorityException>(() => Parse(json.ToJsonString()));
    }
    [Theory]
    [InlineData("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1")]
    [InlineData("\"accountName\":", "\"accountSid\":\"S-1-5-18\",\"accountName\":")]
    public void DuplicatePropertiesAreNotLastValueWins(string from, string to)
        => Assert.Throws<AuthorityException>(() => Parse(Json.Replace(from, to, StringComparison.Ordinal)));
    [Fact]
    public void MalformedEncodingTypesAndOversizedInputFailClosed()
    {
        foreach (var bytes in new[] { Array.Empty<byte>(), new byte[16385], new byte[] { 0xff, 0xff }, Encoding.UTF8.GetBytes("[]"), Encoding.UTF8.GetBytes("{\"schemaVersion\":") })
            Assert.Throws<AuthorityException>(() => AuthorityConfiguration.Parse(bytes));
        Assert.Throws<AuthorityException>(() => Parse(Json.Replace("\"enabled\":true", "\"enabled\":\"true\"", StringComparison.Ordinal)));
    }
    private static AuthorityConfiguration Parse(string json) => AuthorityConfiguration.Parse(Encoding.UTF8.GetBytes(json));
}
