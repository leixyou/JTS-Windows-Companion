using System.Text;
using Microsoft.Data.Sqlite;
using Xunit;
using JTS.WindowsCompanion.Relay;

namespace JTS.WindowsCompanion.Pairing.Tests;

public sealed class PairingCorruptionTests
{
    [Theory]
    [InlineData("UPDATE relay_pairings SET sealed_record=zeroblob(32);")]
    [InlineData("UPDATE relay_pairings SET sealed_record=zeroblob(75777);")]
    [InlineData("UPDATE relay_pairings SET controller_id='cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';")]
    [InlineData("UPDATE relay_pairings SET pairing_id='00000000-0000-4000-8000-000000000001';")]
    [InlineData("UPDATE relay_pairings SET is_current=0;")]
    public void ChangedCiphertextBindingOrSelectorCannotBecomeTrustedInventory(string sql)
    {
        using var f = new PairingFixture(); using var store = f.Create(); store.ApproveLocally(f.Policy(), f.PeerId);
        f.Sql(sql); Assert.Equal("PAIRING_STORE_INVALID", Assert.Throws<PairingStoreException>(() => store.ListLocally()).Code);
    }

    [Theory]
    [InlineData("DELETE FROM pairing_metadata;", "PAIRING_STORE_INVALID")]
    [InlineData("UPDATE pairing_metadata SET seal=zeroblob(32);", "PAIRING_STORE_INVALID")]
    [InlineData("UPDATE pairing_metadata SET local_device='cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';", "PAIRING_STORE_INVALID")]
    [InlineData("PRAGMA user_version=0;", "PAIRING_STORE_VERSION_UNSUPPORTED")]
    [InlineData("PRAGMA user_version=2;", "PAIRING_STORE_VERSION_UNSUPPORTED")]
    public void BadHeaderOrSchemaNeverSilentlyRepairs(string sql, string code)
    {
        using var f = new PairingFixture(); using (f.Create()) { }
        f.Sql(sql); Assert.Equal(code, Assert.Throws<PairingStoreException>(() => f.Open()).Code);
    }

    [Fact]
    public void ValidSealedRecordCannotBeTransplantedIntoAnotherRegistry()
    {
        using var f = new PairingFixture(); using var first = f.Create(); var policy = f.Policy(); first.ApproveLocally(policy, f.PeerId);
        var cipher = Assert.IsType<byte[]>(f.Sql("SELECT sealed_record FROM relay_pairings;"));
        var otherPath = System.IO.Path.Combine(f.Directory.FullName, "other.sqlite");
        using var second = DurableRelayPairingStore.CreateNew(otherPath, f.LocalId, f.Protector, clock: f.Clock);
        second.ApproveLocally(policy, f.PeerId);
        using var db = new SqliteConnection($"Data Source={otherPath};Pooling=False"); db.Open();
        using var command = db.CreateCommand(); command.CommandText = "UPDATE relay_pairings SET sealed_record=$record;";
        command.Parameters.AddWithValue("$record", cipher); command.ExecuteNonQuery();
        Assert.Equal("PAIRING_STORE_INVALID", Assert.Throws<PairingStoreException>(() => second.ListLocally()).Code);
    }

    [Theory]
    [InlineData("version")]
    [InlineData("flag")]
    [InlineData("tls")]
    [InlineData("lanes")]
    [InlineData("count")]
    [InlineData("duplicate")]
    [InlineData("truncated")]
    [InlineData("trailing")]
    public void AuthenticatedMalformedRecordIsStillRejected(string change)
    {
        using var f = new PairingFixture(); using var store = f.Create();
        var policy = f.Policy(grants: new Dictionary<RelayLane, IReadOnlyList<Guid>> { [RelayLane.Control] = [Guid.NewGuid(), Guid.NewGuid()] });
        store.ApproveLocally(policy, f.PeerId);
        var storeId = (string)f.Sql("SELECT store_id FROM pairing_metadata;")!;
        var purpose = Encoding.UTF8.GetBytes($"JTS-DEVICE-PAIRING-V1/record\n{storeId}\n{f.LocalId}\n{f.PeerId}\n{policy.PairingId:D}");
        var bytes = f.Protector.Unprotect((byte[])f.Sql("SELECT sealed_record FROM relay_pairings;")!, purpose);
        switch (change)
        {
            case "version": bytes[0] = 2; break;
            case "flag": bytes[49] = 2; break;
            case "tls": bytes[66] = 99; break;
            case "lanes": bytes[67] = 0; break;
            case "count": bytes[68] = 255; bytes[69] = 255; break;
            case "duplicate": bytes.AsSpan(70, 16).CopyTo(bytes.AsSpan(86, 16)); break;
            case "truncated": bytes = bytes[..48]; break;
            case "trailing": bytes = [.. bytes, 0]; break;
        }
        f.Sql("UPDATE relay_pairings SET sealed_record=$record;", ("$record", f.Protector.Protect(bytes, purpose)));
        Assert.Equal("PAIRING_STORE_INVALID", Assert.Throws<PairingStoreException>(() => store.ListLocally()).Code);
    }

    [Fact]
    public async Task FailedRevocationTransactionDoesNotClaimOrPartiallyCommitRevocation()
    {
        using var f = new PairingFixture(); using var store = f.Create(); var policy = f.Policy(); store.ApproveLocally(policy, f.PeerId);
        f.Sql("CREATE TRIGGER fail_pairing_update BEFORE UPDATE ON relay_pairings BEGIN SELECT RAISE(ABORT,'fixture failure'); END;");
        await Assert.ThrowsAsync<SqliteException>(() => store.RevokeAsync(f.PeerId, policy.PairingId).AsTask());
        Assert.NotNull(await store.FindAsync(f.PeerId)); Assert.Null(Assert.Single(store.ListLocally()).RevokedAt);
        store.Dispose(); using var reopened = f.Open(); Assert.NotNull(await reopened.FindAsync(f.PeerId));
    }
}
