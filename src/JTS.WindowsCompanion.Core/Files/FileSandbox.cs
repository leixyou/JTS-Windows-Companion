namespace JTS.WindowsCompanion.Files;

public sealed class FileSandbox
{
    private readonly IReadOnlyDictionary<string, FileRoot> _roots;
    private readonly StringComparison _pathComparison = OperatingSystem.IsWindows()
        ? StringComparison.OrdinalIgnoreCase
        : StringComparison.Ordinal;

    public FileSandbox(IEnumerable<FileRoot> roots)
    {
        ArgumentNullException.ThrowIfNull(roots);
        var normalized = new Dictionary<string, FileRoot>(StringComparer.Ordinal);
        foreach (var root in roots)
        {
            if (string.IsNullOrWhiteSpace(root.Id) || root.Id.Length > 64)
            {
                throw new ArgumentException("File root IDs must be 1 to 64 characters.", nameof(roots));
            }

            if (root.MaximumFileBytes is <= 0 or > 4L * 1024 * 1024 * 1024)
            {
                throw new ArgumentOutOfRangeException(nameof(roots), "File root size limits must be between 1 byte and 4 GiB.");
            }

            var fullPath = Path.GetFullPath(root.Path);
            if (!Directory.Exists(fullPath))
            {
                throw new DirectoryNotFoundException($"Configured file root '{root.Id}' does not exist.");
            }

            RejectLink(fullPath);
            if (!normalized.TryAdd(root.Id, root with { Path = fullPath }))
            {
                throw new ArgumentException($"Duplicate file root ID '{root.Id}'.", nameof(roots));
            }
        }

        _roots = normalized;
    }

    public IReadOnlyCollection<FileRoot> Roots => _roots.Values.ToArray();

    /// <summary>Listing/stat of an explicitly configured root; mutation still requires a descendant.</summary>
    public SandboxedPath ResolveDirectory(string rootId, string relativePath)
        => relativePath == "." ? ResolveRootDirectory(rootId) : Resolve(rootId, relativePath);

    // Only the current-user shell's exact "." cwd uses this entry point.
    // File operations continue to require a relative descendant path.
    internal SandboxedPath ResolveRootDirectory(string rootId)
    {
        if (!_roots.TryGetValue(rootId, out var root))
        {
            throw new FileSandboxException("ROOT_NOT_ALLOWED", "The requested file root is not allowed.");
        }
        if (!Directory.Exists(root.Path))
        {
            throw new FileSandboxException("PATH_NOT_FOUND", "The configured working directory no longer exists.");
        }
        // The root may have been replaced since this sandbox was constructed.
        RejectLink(root.Path);
        return new SandboxedPath(root, root.Path, ".");
    }

    public SandboxedPath Resolve(string rootId, string relativePath, bool allowMissingLeaf = false)
    {
        if (!_roots.TryGetValue(rootId, out var root))
        {
            throw new FileSandboxException("ROOT_NOT_ALLOWED", "The requested file root is not allowed.");
        }

        var normalizedRelativePath = NormalizeRelativePath(relativePath);
        RejectLink(root.Path);
        var combined = Path.GetFullPath(Path.Combine(root.Path, normalizedRelativePath));
        EnsureWithinRoot(root.Path, combined);
        ValidateExistingSegments(root.Path, normalizedRelativePath, allowMissingLeaf);
        return new SandboxedPath(root, combined, normalizedRelativePath);
    }

    private static string NormalizeRelativePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.IndexOf('\0') >= 0)
        {
            throw new FileSandboxException("PATH_INVALID", "A non-empty relative path is required.");
        }

        if (Path.IsPathRooted(path)
            || path.StartsWith('\\')
            || path.StartsWith('/')
            || (path.Length >= 2 && char.IsLetter(path[0]) && path[1] == ':'))
        {
            throw new FileSandboxException("PATH_ABSOLUTE", "Absolute paths are not accepted.");
        }

        var segments = path
            .Replace('\\', '/')
            .Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0 || segments.Any(segment => segment is "." or ".."))
        {
            throw new FileSandboxException("PATH_TRAVERSAL", "The path contains a traversal segment.");
        }

        return Path.Combine(segments);
    }

    private void EnsureWithinRoot(string root, string candidate)
    {
        var rootPrefix = root.EndsWith(Path.DirectorySeparatorChar)
            ? root
            : root + Path.DirectorySeparatorChar;
        if (!candidate.StartsWith(rootPrefix, _pathComparison))
        {
            throw new FileSandboxException("PATH_ESCAPE", "The path escapes its allowed root.");
        }
    }

    private static void ValidateExistingSegments(string root, string relativePath, bool allowMissingLeaf)
    {
        var segments = relativePath.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
        var current = root;
        for (var index = 0; index < segments.Length; index++)
        {
            current = Path.Combine(current, segments[index]);
            if (!File.Exists(current) && !Directory.Exists(current))
            {
                var isLeaf = index == segments.Length - 1;
                if (!allowMissingLeaf || !isLeaf)
                {
                    throw new FileSandboxException("PATH_NOT_FOUND", "The requested path does not exist.");
                }

                return;
            }

            RejectLink(current);
        }
    }

    private static void RejectLink(string path)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new FileSandboxException("REPARSE_POINT_REJECTED", "Symbolic links and reparse points are not allowed.");
        }
    }
}
