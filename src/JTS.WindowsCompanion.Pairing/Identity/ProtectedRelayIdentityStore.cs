using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.Pairing;

// Injectable storage core is internal. Production entry points fix Windows account/DPAPI/ACL policy.
internal static class ProtectedRelayIdentityStore
{
    internal static StoredRelayIdentity CreateNew(string path, Guid enrollmentId, ITaskPayloadProtector protector,
        TimeProvider clock, Action? verifyAccess = null)
    {
        path = Validate(path, enrollmentId, protector); verifyAccess?.Invoke();
        var lease = Lease(path); X509Certificate2? loaded = null; byte[]? clear = null;
        try
        {
            verifyAccess?.Invoke();
            if (File.Exists(path)) throw new RelayIdentityStoreException("IDENTITY_ALREADY_EXISTS");
            using var generated = RelayIdentityCodec.Generate(clock.GetUtcNow());
            clear = RelayIdentityCodec.Encode(generated, enrollmentId);
            loaded = RelayIdentityCodec.Decode(clear, enrollmentId, null, clock.GetUtcNow());
            var cipher = protector.Protect(clear, RelayIdentityCodec.Purpose(enrollmentId));
            if (cipher is not { Length: > 0 and <= RelayIdentityCodec.MaximumCiphertext }) throw RelayIdentityCodec.Invalid();
            // Only ciphertext touches our file. A partial write is retained as invalid state, never auto-regenerated.
            using (var output = OpenFile(path, FileMode.CreateNew, FileAccess.Write))
            { output.Write(cipher); output.Flush(flushToDisk: true); }
            verifyAccess?.Invoke();
            return new(loaded, lease);
        }
        catch { loaded?.Dispose(); lease.Dispose(); throw; }
        finally { if (clear is not null) CryptographicOperations.ZeroMemory(clear); }
    }

    internal static StoredRelayIdentity Open(string path, Guid enrollmentId, string expectedDeviceId,
        ITaskPayloadProtector protector, TimeProvider clock, Action? verifyAccess = null)
    {
        PairingValidation.Device(expectedDeviceId);
        path = Validate(path, enrollmentId, protector); verifyAccess?.Invoke();
        if (!File.Exists(path)) throw new RelayIdentityStoreException("IDENTITY_NOT_INITIALIZED");
        var lease = Lease(path); X509Certificate2? loaded = null; byte[]? clear = null;
        try
        {
            verifyAccess?.Invoke();
            using (var input = OpenFile(path, FileMode.Open, FileAccess.Read))
            {
                if (input.Length is < 1 or > RelayIdentityCodec.MaximumCiphertext) throw RelayIdentityCodec.Invalid();
                var cipher = new byte[(int)input.Length]; input.ReadExactly(cipher);
                if (input.ReadByte() != -1) throw RelayIdentityCodec.Invalid();
                clear = protector.Unprotect(cipher, RelayIdentityCodec.Purpose(enrollmentId));
            }
            if (clear is null) throw RelayIdentityCodec.Invalid();
            loaded = RelayIdentityCodec.Decode(clear, enrollmentId, expectedDeviceId, clock.GetUtcNow());
            return new(loaded, lease);
        }
        catch (CryptographicException) { loaded?.Dispose(); lease.Dispose(); throw RelayIdentityCodec.Invalid(); }
        catch { loaded?.Dispose(); lease.Dispose(); throw; }
        finally { if (clear is not null) CryptographicOperations.ZeroMemory(clear); }
    }
    private static string Validate(string path, Guid enrollmentId, ITaskPayloadProtector protector)
    {
        ArgumentNullException.ThrowIfNull(protector);
        if (enrollmentId == Guid.Empty) throw new ArgumentException("An explicit installation enrollment ID is required.");
        return PairingStorePath.Validate(path);
    }
    private static FileStream Lease(string path) => OpenFile(path + ".lease", FileMode.OpenOrCreate, FileAccess.ReadWrite);
    private static FileStream OpenFile(string path, FileMode mode, FileAccess access)
    {
        var options = new FileStreamOptions { Mode = mode, Access = access, Share = FileShare.None,
            Options = access == FileAccess.Read ? FileOptions.SequentialScan : FileOptions.WriteThrough };
        if (!OperatingSystem.IsWindows() && mode != FileMode.Open)
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        return new(path, options);
    }
}
