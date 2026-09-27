using System.Text;
using Xunit;

namespace JTS.WindowsCompanion.Control.Tests;

public sealed class ControlPolicyCorruptionTests
{
    [Theory]
    [InlineData("UPDATE control_grants SET sealed_record=zeroblob(32);")]
    [InlineData("UPDATE control_grants SET sealed_record=zeroblob(12289);")]
    [InlineData("UPDATE control_grants SET owner='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';")]
    public async Task AlteredBoundCiphertextOrOversizedRecordCannotAuthorize(string mutation)
    {
        using var f = new ControlPolicyFixture(); using var store = f.Create(); var grant = f.Grant(); store.ApproveLocally(grant);
        f.Sql(mutation);
        Assert.Equal("CONTROL_POLICY_INVALID", (await Assert.ThrowsAsync<ControlPolicyException>(() => store.FindAsync(f.Owner, grant.GrantId, default).AsTask())).Code);
    }

    [Fact]
    public async Task ValidCiphertextCannotBeMovedToAnotherStoreOrGrantIdentifier()
    {
        using var f = new ControlPolicyFixture(); var grant = f.Grant();
        using var store = f.Create(); store.ApproveLocally(grant);
        var cipher = Assert.IsType<byte[]>(f.Sql("SELECT sealed_record FROM control_grants;"));
        var changedId = Guid.NewGuid();
        f.Sql("UPDATE control_grants SET grant_id=$id;", ("$id", changedId.ToString("D")));
        await Assert.ThrowsAsync<ControlPolicyException>(() => store.FindAsync(f.Owner, changedId, default).AsTask());
        var otherPath = Path.Combine(f.Directory.FullName, "other.sqlite");
        using var other = DurableControlGrantStore.CreateNew(otherPath, f.Protector, clock: f.Clock);
        other.ApproveLocally(grant);
        using var db = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={otherPath};Pooling=False"); db.Open();
        using var command = db.CreateCommand(); command.CommandText = "UPDATE control_grants SET sealed_record=$cipher;";
        command.Parameters.AddWithValue("$cipher", cipher); command.ExecuteNonQuery();
        await Assert.ThrowsAsync<ControlPolicyException>(() => other.FindAsync(f.Owner, grant.GrantId, default).AsTask());
    }

    [Theory]
    [InlineData("PRAGMA user_version=99;", "CONTROL_POLICY_VERSION_UNSUPPORTED")]
    [InlineData("UPDATE policy_metadata SET store_id='00000000-0000-4000-8000-000000000001';", "CONTROL_POLICY_INVALID")]
    [InlineData("UPDATE policy_metadata SET seal=zeroblob(32);", "CONTROL_POLICY_INVALID")]
    public void DamagedHeaderOrNewerSchemaRefusesStartup(string mutation, string code)
    {
        using var f = new ControlPolicyFixture(); using (var store = f.Create()) { }
        f.Sql(mutation);
        Assert.Equal(code, Assert.Throws<ControlPolicyException>(() => f.Open()).Code);
    }

    [Fact]
    public void AuthenticatedButMalformedRecordIsStillRejected()
    {
        using var f = new ControlPolicyFixture(); using var store = f.Create(); var grant = f.Grant(); store.ApproveLocally(grant);
        var storeId = (string)f.Sql("SELECT store_id FROM policy_metadata;")!;
        var purpose = Encoding.UTF8.GetBytes($"JTS-COMPANION-CONTROL-POLICY-V1/record\n{storeId}\n{f.Owner}\n{grant.GrantId:D}");
        var malformed = Encoding.UTF8.GetBytes("{\"version\":1,\"version\":1}");
        f.Sql("UPDATE control_grants SET sealed_record=$record;", ("$record", f.Protector.Protect(malformed, purpose)));
        Assert.Equal("CONTROL_POLICY_INVALID", Assert.Throws<ControlPolicyException>(() => store.ListLocally()).Code);
    }
}
