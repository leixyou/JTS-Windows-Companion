using System.Text.Json;
using System.Text.Json.Serialization;

namespace JTS.WindowsCompanion.UnattendedInstallation;

// Parent directory and operation lease are installer-private in the native composition.
// Existing journals are never automatically resumed, replaced or interpreted as account ownership.
internal sealed class InstallJournal
{
    private static readonly JsonSerializerOptions Json = new() { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    private readonly string _path;
    internal InstallSnapshot Current { get; private set; }
    internal InstallJournal(string path, InstallSnapshot initial)
    {
        _path = Path.GetFullPath(path); initial.Validate();
        if (initial.Phase != InstallPhase.Prepared || initial.Authority is not null || initial.Worker is not null || initial.DeviceId is not null)
            throw new UnattendedInstallationException("INSTALL_INITIAL_JOURNAL_INVALID");
        Current = initial; Write(initial, createNew: true);
    }
    internal void Save(InstallSnapshot next)
    {
        next.Validate();
        if (next.EnrollmentId != Current.EnrollmentId || next.ReleaseHash != Current.ReleaseHash || next.ReleaseId != Current.ReleaseId
            || next.RelayOrigin != Current.RelayOrigin || (Current.Authority is not null && next.Authority != Current.Authority)
            || (Current.Worker is not null && next.Worker != Current.Worker) || (Current.DeviceId is not null && next.DeviceId != Current.DeviceId))
            throw new UnattendedInstallationException("INSTALL_JOURNAL_BINDING_MISMATCH");
        if (!Transition(Current.Phase, next.Phase)) throw new UnattendedInstallationException("INSTALL_JOURNAL_TRANSITION_REJECTED");
        Write(next, createNew: false); Current = next;
    }
    internal static InstallSnapshot Read(string path)
    {
        try
        {
            RejectLinks(path);
            using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (input.Length is < 1 or > 16384) throw new UnattendedInstallationException("INSTALL_JOURNAL_INVALID");
            var bytes = new byte[(int)input.Length]; input.ReadExactly(bytes);
            _ = new System.Text.UTF8Encoding(false, true).GetString(bytes);
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4 });
            RejectDuplicates(document.RootElement);
            var snapshot = JsonSerializer.Deserialize<InstallSnapshot>(bytes, Json) ?? throw new JsonException(); snapshot.Validate(); return snapshot;
        }
        catch (Exception error) when (error is JsonException or ArgumentException or InvalidOperationException)
        { throw new UnattendedInstallationException("INSTALL_JOURNAL_INVALID"); }
    }
    private void Write(InstallSnapshot value, bool createNew)
    {
        RejectLinks(_path);
        var pending = _path + ".pending";
        RejectLinks(pending);
        // Never overwrite a prior interrupted journal update. It needs explicit local diagnosis.
        using (var output = new FileStream(pending, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        { output.Write(JsonSerializer.SerializeToUtf8Bytes(value, Json)); output.Flush(flushToDisk: true); }
        File.Move(pending, _path, overwrite: !createNew);
    }
    private static bool Transition(InstallPhase current, InstallPhase next)
    {
        if (current is InstallPhase.Active or InstallPhase.RolledBack or InstallPhase.RepairRequired) return false;
        if (next == InstallPhase.RepairRequired) return true;
        if (next == InstallPhase.RollbackStarted) return current < InstallPhase.Activating;
        if (current == InstallPhase.RollbackStarted) return next == InstallPhase.RolledBack;
        return (int)next == (int)current + 1;
    }
    internal static void RejectLinks(string path)
    {
        for (string? item = Path.GetFullPath(path); item is not null; item = Path.GetDirectoryName(item))
        {
            try { if ((File.GetAttributes(item) & FileAttributes.ReparsePoint) != 0) throw new UnattendedInstallationException("INSTALL_LINK_REJECTED"); }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
        }
    }
    private static void RejectDuplicates(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object) return;
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        { if (!names.Add(property.Name)) throw new JsonException(); RejectDuplicates(property.Value); }
    }
}
