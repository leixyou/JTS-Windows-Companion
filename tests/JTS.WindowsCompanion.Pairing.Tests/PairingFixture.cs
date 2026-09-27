using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using JTS.WindowsCompanion.Relay;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.Pairing.Tests;

internal sealed class PairingFixture : IDisposable
{
    internal DirectoryInfo Directory { get; } = System.IO.Directory.CreateTempSubdirectory("jts-device-pairing-");
    internal string Path => System.IO.Path.Combine(Directory.FullName, "pairings.sqlite");
    internal string LocalId { get; } = new('a', 64);
    internal string PeerId { get; } = new('b', 64);
    internal TestProtector Protector { get; } = new();
    internal TestClock Clock { get; } = new();
    internal PairingFixture()
    {
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(Directory.FullName, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }
    internal DurableRelayPairingStore Create(int capacity = 256) => DurableRelayPairingStore.CreateNew(Path, LocalId, Protector, capacity, Clock);
    internal DurableRelayPairingStore Open(int capacity = 256) => new(Path, LocalId, Protector, capacity, Clock);
    internal RelayDevicePairing Policy(Guid? id = null, string? peer = null, RelayTlsPolicy tls = RelayTlsPolicy.Tls13,
        RelayLane[]? lanes = null, IReadOnlyDictionary<RelayLane, IReadOnlyList<Guid>>? grants = null)
        => new(id ?? Guid.NewGuid(), peer ?? PeerId, tls, Clock.GetUtcNow().AddHours(1), lanes ?? [RelayLane.Control], grants);
    internal object? Sql(string sql, params (string Name, object Value)[] args)
    {
        using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = Path, Pooling = false }.ToString());
        db.Open(); using var command = db.CreateCommand(); command.CommandText = sql;
        foreach (var arg in args) command.Parameters.AddWithValue(arg.Name, arg.Value);
        return command.ExecuteScalar();
    }
    public void Dispose() { Protector.Dispose(); Directory.Delete(true); }
}

internal sealed class TestClock : TimeProvider
{
    private DateTimeOffset _now = new(2026, 9, 19, 0, 0, 0, TimeSpan.Zero);
    public override DateTimeOffset GetUtcNow() => _now;
    internal void Advance(TimeSpan span) => _now += span;
}

internal sealed class TestProtector : ITaskPayloadProtector, IDisposable
{
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    public byte[] Protect(ReadOnlySpan<byte> plain, ReadOnlySpan<byte> purpose)
    {
        var result = new byte[28 + plain.Length]; RandomNumberGenerator.Fill(result.AsSpan(0, 12));
        using var aes = new AesGcm(_key, 16); aes.Encrypt(result.AsSpan(0, 12), plain, result.AsSpan(28), result.AsSpan(12, 16), purpose); return result;
    }
    public byte[] Unprotect(ReadOnlySpan<byte> cipher, ReadOnlySpan<byte> purpose)
    {
        if (cipher.Length < 28) throw new CryptographicException();
        var result = new byte[cipher.Length - 28]; using var aes = new AesGcm(_key, 16);
        aes.Decrypt(cipher[..12], cipher[28..], cipher.Slice(12, 16), result, purpose); return result;
    }
    public void Dispose() => CryptographicOperations.ZeroMemory(_key);
}
