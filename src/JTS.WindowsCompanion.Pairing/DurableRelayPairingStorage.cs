using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace JTS.WindowsCompanion.Pairing;

public sealed partial class DurableRelayPairingStore
{
    private static readonly byte[] HeaderPurpose = Encoding.UTF8.GetBytes("JTS-DEVICE-PAIRING-V1/header");
    private Guid Initialize()
    {
        var id = Guid.NewGuid(); var clear = Header(id); byte[] cipher;
        try { cipher = _protector.Protect(clear, HeaderPurpose); }
        finally { CryptographicOperations.ZeroMemory(clear); }
        if (cipher is not { Length: > 0 and <= RelayPairingCodec.MaximumCiphertext }) throw PairingValidation.Invalid();
        using var transaction = _db.BeginTransaction();
        using var schema = Command("""
            CREATE TABLE pairing_metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1),store_id TEXT NOT NULL,local_device TEXT NOT NULL,seal BLOB NOT NULL);
            CREATE TABLE relay_pairings(pairing_id TEXT PRIMARY KEY,controller_id TEXT NOT NULL,is_current INTEGER NOT NULL CHECK(is_current IN (0,1)),sealed_record BLOB NOT NULL);
            CREATE UNIQUE INDEX pairing_current ON relay_pairings(controller_id) WHERE is_current=1;
            PRAGMA user_version=1;
            """);
        schema.Transaction = transaction; schema.ExecuteNonQuery();
        using var insert = Command("INSERT INTO pairing_metadata VALUES(1,$id,$local,$seal);",
            ("$id", id.ToString("D")), ("$local", LocalDeviceId), ("$seal", cipher));
        insert.Transaction = transaction; insert.ExecuteNonQuery(); transaction.Commit(); return id;
    }
    private Guid AuthenticateHeader()
    {
        if (Convert.ToInt32(Scalar("PRAGMA user_version;")) != 1) throw new PairingStoreException("PAIRING_STORE_VERSION_UNSUPPORTED");
        using var command = Command("SELECT store_id,local_device,length(seal),seal FROM pairing_metadata WHERE singleton=1;");
        using var reader = command.ExecuteReader();
        if (!reader.Read() || reader.GetString(1) != LocalDeviceId || reader.GetInt64(2) is < 1 or > RelayPairingCodec.MaximumCiphertext)
            throw PairingValidation.Invalid();
        var id = ParseId(reader.GetString(0)); byte[]? clear = null;
        try
        {
            clear = _protector.Unprotect((byte[])reader.GetValue(3), HeaderPurpose);
            if (clear is null || !CryptographicOperations.FixedTimeEquals(clear, Header(id))) throw PairingValidation.Invalid();
        }
        catch (CryptographicException) { throw PairingValidation.Invalid(); }
        finally { if (clear is not null) CryptographicOperations.ZeroMemory(clear); }
        return id;
    }
    private RelayPairingRecord? Current(string owner)
    {
        using var command = Command("SELECT pairing_id FROM relay_pairings WHERE controller_id=$owner AND is_current=1;", ("$owner", owner));
        var ids = new List<Guid>();
        using (var reader = command.ExecuteReader()) while (reader.Read())
        {
            if (ids.Count != 0) throw PairingValidation.Invalid();
            ids.Add(ParseId(reader.GetString(0)));
        }
        if (ids.Count == 0) return null;
        var record = Read(ids[0]);
        if (record is null || record.ControllerDeviceId != owner || record.RevokedAt is not null || record.Policy is null) throw PairingValidation.Invalid();
        return record;
    }
    private RelayPairingRecord? Read(Guid id)
    {
        using var command = Command("SELECT controller_id,is_current,length(sealed_record),sealed_record FROM relay_pairings WHERE pairing_id=$id;", ("$id", id.ToString("D")));
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        if (reader.GetInt64(2) is < 1 or > RelayPairingCodec.MaximumCiphertext) throw PairingValidation.Invalid();
        var owner = reader.GetString(0); PairingValidation.Identity(owner, id);
        if (owner == LocalDeviceId) throw PairingValidation.Invalid();
        var record = RelayPairingCodec.Open((byte[])reader.GetValue(3), owner, id, _protector, Purpose(owner, id));
        if (reader.GetInt64(1) != (record.RevokedAt is null ? 1 : 0)) throw PairingValidation.Invalid();
        return record;
    }
    private void Write(RelayPairingRecord record, bool insert)
    {
        var cipher = RelayPairingCodec.Seal(record, _protector, Purpose(record.ControllerDeviceId, record.PairingId));
        using var transaction = _db.BeginTransaction();
        using var command = Command(insert
            ? "INSERT INTO relay_pairings VALUES($id,$owner,$current,$record);"
            : "UPDATE relay_pairings SET is_current=$current,sealed_record=$record WHERE pairing_id=$id AND controller_id=$owner;",
            ("$id", record.PairingId.ToString("D")), ("$owner", record.ControllerDeviceId),
            ("$current", record.RevokedAt is null ? 1 : 0), ("$record", cipher));
        command.Transaction = transaction;
        if (command.ExecuteNonQuery() != 1) throw PairingValidation.Invalid();
        transaction.Commit();
    }
    private byte[] Header(Guid id) => Encoding.UTF8.GetBytes($"JTS-DEVICE-PAIRING-V1\n{id:D}\n{LocalDeviceId}");
    private byte[] Purpose(string owner, Guid id) => Encoding.UTF8.GetBytes($"JTS-DEVICE-PAIRING-V1/record\n{_storeId:D}\n{LocalDeviceId}\n{owner}\n{id:D}");
    private static Guid ParseId(string value)
    {
        if (!Guid.TryParseExact(value, "D", out var id) || id == Guid.Empty || value != id.ToString("D")) throw PairingValidation.Invalid();
        return id;
    }
    private SqliteCommand Command(string sql, params (string Key, object Value)[] args)
    {
        var command = _db.CreateCommand(); command.CommandText = sql;
        foreach (var arg in args) command.Parameters.AddWithValue(arg.Key, arg.Value);
        return command;
    }
    private object? Scalar(string sql) { using var command = Command(sql); return command.ExecuteScalar(); }
    private void Execute(string sql) { using var command = Command(sql); command.ExecuteNonQuery(); }
}
