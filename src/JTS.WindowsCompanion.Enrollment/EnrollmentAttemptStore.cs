using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.Enrollment;

internal sealed record EnrollmentAttempt(Guid InvitationId, string RelayOrigin, string SecretBase64, string State,
    DateTimeOffset CreatedAt, string? OfferBase64 = null, string? RequestBase64 = null, string? RequestSha256 = null,
    string? ControllerDeviceId = null, string? ResponseBase64 = null, string? SignatureBase64 = null, string? ClaimHash = null,
    long? ExpiresAtUnixSeconds = null, DateTimeOffset? VerifiedAt = null, string? ErrorCode = null)
{
    internal EnrollmentCode OpenCode() => new(RelayOrigin, InvitationId, EnrollmentCrypto.Base64(SecretBase64, 32));
    public override string ToString() => $"EnrollmentAttempt ({State}; secret omitted)";
}

internal sealed class EnrollmentAttemptStore : IDisposable
{
    private sealed record Document(int Version, string DeviceId, List<EnrollmentAttempt> Attempts);
    private static readonly JsonSerializerOptions Options = new() { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    private readonly string _path;
    private readonly string _device;
    private readonly ITaskPayloadProtector _protector;
    private readonly Action<string> _check;
    private readonly FileStream _lease;
    private readonly byte[] _purpose;
    internal List<EnrollmentAttempt> Attempts { get; private set; }
    internal EnrollmentAttemptStore(string path, string device, ITaskPayloadProtector protector, Action<string> check)
    {
        _path = path; _device = device; _protector = protector; _check = check;
        _purpose = Encoding.UTF8.GetBytes("JTS-ENROLLMENT-ATTEMPTS-1\n" + device);
        check(path); check(path + ".lease"); check(path + ".pending");
        _lease = new(path + ".lease", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        try
        {
            if (File.Exists(path + ".pending"))
            {
                _ = Read(path + ".pending");
                File.Move(path + ".pending", path, overwrite: true); // A fully flushed, authenticated pending commit is replayable.
            }
            Attempts = File.Exists(path) ? Read(path) : [];
        }
        catch { _lease.Dispose(); throw; }
    }
    private List<EnrollmentAttempt> Read(string path)
    {
        _check(path);
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is < 1 or > 4194304) throw Invalid();
        var cipher = new byte[(int)file.Length]; file.ReadExactly(cipher);
        var clear = _protector.Unprotect(cipher, _purpose);
        try
        {
            var value = JsonSerializer.Deserialize<Document>(clear, Options) ?? throw Invalid();
            if (value.Version != 1 || value.DeviceId != _device || value.Attempts.Count > 64
                || value.Attempts.Select(a => a.InvitationId).Distinct().Count() != value.Attempts.Count) throw Invalid();
            foreach (var a in value.Attempts)
            {
                if (a.InvitationId == Guid.Empty || a.RelayOrigin != EnrollmentCode.CanonicalOrigin(a.RelayOrigin)
                    || a.State is not ("pending" or "claimed" or "committing" or "bound" or "revoking" or "revoked" or "cancelled" or "expired" or "faulted")) throw Invalid();
                if (a.State is "pending" or "claimed" && EnrollmentCrypto.Base64(a.SecretBase64, 32).Length != 32) throw Invalid();
                if (a.ResponseBase64 is not null && (a.RequestBase64 is null || a.RequestSha256 is null || a.OfferBase64 is null
                    || a.ControllerDeviceId is null || a.SignatureBase64 is null || a.ClaimHash is null || a.VerifiedAt is null)) throw Invalid();
            }
            return value.Attempts;
        }
        catch (Exception e) when (e is JsonException or NullReferenceException) { throw Invalid(); }
        finally { CryptographicOperations.ZeroMemory(clear); }
    }
    internal void Save(EnrollmentAttempt attempt)
    {
        var copy = Attempts.Where(a => a.InvitationId != attempt.InvitationId).Append(attempt).ToList();
        if (copy.Count > 64) throw new EnrollmentException("ENROLLMENT_CAPACITY");
        var clear = JsonSerializer.SerializeToUtf8Bytes(new Document(1, _device, copy), Options);
        byte[] cipher;
        try { cipher = _protector.Protect(clear, _purpose); }
        finally { CryptographicOperations.ZeroMemory(clear); }
        _check(_path); _check(_path + ".pending");
        using (var file = new FileStream(_path + ".pending", FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        { file.Write(cipher); file.Flush(flushToDisk: true); }
        File.Move(_path + ".pending", _path, overwrite: true);
        Attempts = copy;
    }
    private static EnrollmentException Invalid() => new("ENROLLMENT_STATE_INVALID");
    public void Dispose() => _lease.Dispose();
}
