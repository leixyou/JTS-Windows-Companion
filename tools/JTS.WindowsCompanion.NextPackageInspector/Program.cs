using System.Buffers.Binary;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JTS.WindowsCompanion.Security;

// Packaging verifier only. Does not load/execute any inspected assembly or native payload.
if (args.Length != 4) { Console.Error.WriteLine("Expected Core assembly, public key, manifest, payload directory."); return 2; }
try
{
    var core = Read(args[0], 16 * 1024 * 1024);
    var key = Read(args[1], 4096);
    var manifest = Read(args[2], 65536);
    using var stream = new MemoryStream(core, writable: false);
    using var pe = new PEReader(stream);
    var metadata = pe.GetMetadataReader();
    var resources = pe.PEHeaders.CorHeader?.ResourcesDirectory ?? throw new InvalidDataException();
    var matched = 0;
    foreach (var handle in metadata.ManifestResources)
    {
        var resource = metadata.GetManifestResource(handle);
        if (metadata.GetString(resource.Name) != "JTS.Companion.ReleasePublicKey") continue;
        if (!resource.Implementation.IsNil) throw new InvalidDataException();
        var content = pe.GetSectionData(checked(resources.RelativeVirtualAddress + (int)resource.Offset));
        var length = BinaryPrimitives.ReadInt32LittleEndian(content.GetContent(0, 4).AsSpan());
        if (length != key.Length || !content.GetContent(4, length).AsSpan().SequenceEqual(key)) throw new InvalidDataException();
        matched++;
    }
    if (matched != 1) throw new InvalidDataException();
    var release = ReleaseManifestTrust.Verify(manifest, new UTF8Encoding(false, true).GetString(key));
    if (release.SchemaVersion != 2) throw new InvalidDataException();
    var root = Path.GetFullPath(args[3]);
    var files = Directory.GetFileSystemEntries(root);
    var expected = new HashSet<string>(release.FileNames, StringComparer.Ordinal) { ReleaseManifestTrust.ManifestFileName };
    if (files.Length != expected.Count || files.Any(p => !expected.Remove(Path.GetFileName(p))
        || (File.GetAttributes(p) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)) throw new InvalidDataException();
    if (!File.ReadAllBytes(Path.Combine(root, ReleaseManifestTrust.ManifestFileName)).AsSpan().SequenceEqual(manifest)) throw new InvalidDataException();
    foreach (var name in release.FileNames) release.VerifyFile(Path.Combine(root, name), name);
    Console.WriteLine(JsonSerializer.Serialize(new { schemaVersion = 2, releaseId = release.ReleaseId,
        files = release.FileNames.Count, coreSha256 = Hash(core), publicKeySha256 = Hash(key), manifestSha256 = Hash(manifest) }));
    return 0;
}
catch { Console.Error.WriteLine("NEXT_PACKAGE_INSPECTION_FAILED"); return 1; }

static byte[] Read(string path, int limit)
{
    using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
    if (file.Length < 1 || file.Length > limit || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException();
    var bytes = new byte[(int)file.Length]; file.ReadExactly(bytes); return bytes;
}
static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
