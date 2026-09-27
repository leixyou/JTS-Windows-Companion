using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace JTS.WindowsCompanion.Control;

public sealed partial class DurableControlGrantStore
{
    private static readonly byte[] HeaderPurpose = Encoding.UTF8.GetBytes("JTS-COMPANION-CONTROL-POLICY-V1/header");
    private Guid Initialize()
    {
        var id = Guid.NewGuid(); var clear = Header(id);
        var cipher = _protector.Protect(clear, HeaderPurpose);
        if (cipher is not { Length: > 0 and <= ControlPolicyCodec.MaximumCiphertext }) throw ControlPolicyCodec.Invalid();
        using var transaction = _db.BeginTransaction();
        using var schema = Command("""
            CREATE TABLE policy_metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1),store_id TEXT NOT NULL,seal BLOB NOT NULL);
            CREATE TABLE control_grants(grant_id TEXT PRIMARY KEY,owner TEXT NOT NULL,sealed_record BLOB NOT NULL);
            PRAGMA user_version=1;
            """);
        schema.Transaction = transaction; schema.ExecuteNonQuery();
        using var insert = Command("INSERT INTO policy_metadata VALUES(1,$id,$seal);", ("$id", id.ToString("D")), ("$seal", cipher));
        insert.Transaction = transaction; insert.ExecuteNonQuery(); transaction.Commit();
        return id;
    }
    private Guid AuthenticateHeader()
    {
        if (Convert.ToInt32(Scalar("PRAGMA user_version;")) != 1)
            throw new ControlPolicyException("CONTROL_POLICY_VERSION_UNSUPPORTED");
        using var command = Command("SELECT store_id,length(seal),seal FROM policy_metadata WHERE singleton=1;");
        using var reader = command.ExecuteReader();
        if (!reader.Read() || reader.GetInt64(1) is < 1 or > ControlPolicyCodec.MaximumCiphertext) throw ControlPolicyCodec.Invalid();
        var id = ParseId(reader.GetString(0)); byte[]? clear = null;
        try
        {
            clear = _protector.Unprotect((byte[])reader.GetValue(2), HeaderPurpose);
            if (clear is null || !CryptographicOperations.FixedTimeEquals(clear, Header(id))) throw ControlPolicyCodec.Invalid();
        }
        catch (CryptographicException) { throw ControlPolicyCodec.Invalid(); }
        finally { if (clear is not null) CryptographicOperations.ZeroMemory(clear); }
        return id;
    }
    private ControlPolicyRecord? Read(Guid id)
    {
        using var command = Command("SELECT owner,length(sealed_record),sealed_record FROM control_grants WHERE grant_id=$id;", ("$id", id.ToString("D")));
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        if (reader.GetInt64(1) is < 1 or > ControlPolicyCodec.MaximumCiphertext) throw ControlPolicyCodec.Invalid();
        var owner = reader.GetString(0); ControlPolicyCodec.Identity(owner, id);
        return ControlPolicyCodec.Open((byte[])reader.GetValue(2), owner, id, _protector, Purpose(owner, id));
    }
    private void Write(ControlPolicyRecord record, bool insert)
    {
        var cipher = ControlPolicyCodec.Seal(record, _protector, Purpose(record.OwnerDeviceId, record.GrantId));
        using var transaction = _db.BeginTransaction();
        using var command = Command(insert
            ? "INSERT INTO control_grants(grant_id,owner,sealed_record) VALUES($id,$owner,$record);"
            : "UPDATE control_grants SET sealed_record=$record WHERE grant_id=$id AND owner=$owner;",
            ("$id", record.GrantId.ToString("D")), ("$owner", record.OwnerDeviceId), ("$record", cipher));
        command.Transaction = transaction;
        if (command.ExecuteNonQuery() != 1) throw ControlPolicyCodec.Invalid();
        transaction.Commit();
    }

    private byte[] Purpose(string owner, Guid id) => Encoding.UTF8.GetBytes($"JTS-COMPANION-CONTROL-POLICY-V1/record\n{_storeId:D}\n{owner}\n{id:D}");
    private static byte[] Header(Guid id) => Encoding.UTF8.GetBytes($"JTS-COMPANION-CONTROL-POLICY-V1\n{id:D}");
    private static Guid ParseId(string text)
    {
        if (!Guid.TryParseExact(text, "D", out var id) || id == Guid.Empty || text != id.ToString("D")) throw ControlPolicyCodec.Invalid();
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

    private static string ValidatePath(string path)
    {
        if (!Path.IsPathFullyQualified(path)) throw new ArgumentException("An absolute private policy database path is required.");
        path = Path.GetFullPath(path); var parent = Path.GetDirectoryName(path)!;
        if (!Directory.Exists(parent)) throw new ArgumentException("Provision the private policy directory before opening it.");
        foreach (var item in new[] { parent, path, path + ".lease", path + "-wal", path + "-shm" }) RejectLinks(item);
        if (!OperatingSystem.IsWindows() && (File.GetUnixFileMode(parent)
            & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
            throw new ArgumentException("The policy directory must not be group/world writable.");
        return path;
    }
    private static void RejectLinks(string path)
    {
        string? current = path;
        do
        {
            if (new FileInfo(current).LinkTarget is not null
                || ((File.Exists(current) || Directory.Exists(current)) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0))
                throw new ArgumentException("The policy database path cannot traverse a reparse point.");
            current = OperatingSystem.IsWindows() ? Path.GetDirectoryName(current) : null;
        } while (!string.IsNullOrEmpty(current));
    }
}
