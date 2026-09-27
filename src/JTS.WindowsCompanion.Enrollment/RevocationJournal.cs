using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.Enrollment;

internal sealed record RevocationEntry(RevocationDelivery Delivery, RevocationReceipt? Receipt = null, bool Delivered = false, bool Rejected = false);

/// <summary>One Authority-owned sealed journal. A signed receipt is flushed before any network acknowledgement.</summary>
internal sealed class RevocationJournal : IDisposable
{
    private sealed record Document(int Version, string DeviceId, List<RevocationEntry> Entries);
    private static readonly JsonSerializerOptions Options = new() { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    private readonly string _path, _device;
    private readonly ITaskPayloadProtector _protector;
    private readonly Action<string> _check;
    private readonly byte[] _purpose;
    private readonly FileStream _lease;
    internal List<RevocationEntry> Entries { get; private set; }
    internal RevocationJournal(string path, string device, ITaskPayloadProtector protector, Action<string> check)
    {
        _path = path; _device = device; _protector = protector; _check = check;
        _purpose = Encoding.UTF8.GetBytes("JTS-REVOCATIONS-2\n" + device);
        check(path); check(path + ".pending"); check(path + ".lease");
        _lease = new(path + ".lease", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        try
        {
            if (File.Exists(path + ".pending")) { _ = Read(path + ".pending"); File.Move(path + ".pending", path, true); }
            Entries = File.Exists(path) ? Read(path) : [];
        }
        catch { _lease.Dispose(); throw; }
    }
    private List<RevocationEntry> Read(string path)
    {
        _check(path); using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is < 1 or > 2097152) throw RevocationRequest.Invalid();
        var cipher = new byte[(int)file.Length]; file.ReadExactly(cipher); var clear = _protector.Unprotect(cipher, _purpose);
        try
        {
            var document = JsonSerializer.Deserialize<Document>(clear, Options) ?? throw RevocationRequest.Invalid();
            if (document.Version != 2 || document.DeviceId != _device || document.Entries.Count > 256
                || document.Entries.Select(e => e.Delivery.Revocation.RevocationId).Distinct().Count() != document.Entries.Count)
                throw RevocationRequest.Invalid();
            return document.Entries;
        }
        finally { CryptographicOperations.ZeroMemory(clear); }
    }
    internal void Save(RevocationEntry entry)
    {
        var copy = Entries.Where(e => e.Delivery.Revocation.RevocationId != entry.Delivery.Revocation.RevocationId).Append(entry).ToList();
        if (copy.Count > 256) throw new EnrollmentException("REVOCATION_CAPACITY");
        var clear = JsonSerializer.SerializeToUtf8Bytes(new Document(2, _device, copy), Options); byte[] cipher;
        try { cipher = _protector.Protect(clear, _purpose); } finally { CryptographicOperations.ZeroMemory(clear); }
        _check(_path); _check(_path + ".pending");
        using (var file = new FileStream(_path + ".pending", FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        { file.Write(cipher); file.Flush(true); }
        File.Move(_path + ".pending", _path, true); Entries = copy;
    }
    public void Dispose() => _lease.Dispose();
}
