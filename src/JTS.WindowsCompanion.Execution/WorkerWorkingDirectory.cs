namespace JTS.WindowsCompanion.Execution;

internal static class WorkerWorkingDirectory
{
    internal static string Resolve(string requested, string commonData)
    {
        if (requested != ".") return requested;
        var root = Path.Combine(commonData, "JTS Terminal", "Companion25", "shared");
        if (!Directory.Exists(root)) throw new InvalidOperationException("WORKER_DIRECTORY_REJECTED");
        // Recheck on every launch: an approved root may have changed since installation.
        for (string? current = root; current is not null; current = Path.GetDirectoryName(current))
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("WORKER_DIRECTORY_REJECTED");
        return root;
    }
}
