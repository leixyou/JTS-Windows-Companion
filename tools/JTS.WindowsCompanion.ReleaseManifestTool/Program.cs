namespace JTS.WindowsCompanion.ReleaseManifestTool;

internal static class Program
{
    private const string Usage = """
        JTS Windows Companion release manifest tool (.NET 8)
          keygen --private-key <new-private.pem>
          public-key --private-key <private.pem> --output <new-public.pem>
          sign --private-key <private.pem> --release-id <id> --output <new-release.json> --file <payload.exe> [--file <payload.exe> ...]
          sign-bundle --private-key <private.pem> --release-id <id> --output <new-release.json> --file <payload.exe-or-dll> [--file <payload.exe-or-dll> ...]
        Private keys are never printed or copied into release artifacts. Outputs must not exist.
        """;

    public static int Main(string[] args)
    {
        if (args.Length == 0 || args is ["--help"] or ["-h"])
        {
            Console.WriteLine(Usage);
            return args.Length == 0 ? 2 : 0;
        }

        try
        {
            var options = new Dictionary<string, string>(StringComparer.Ordinal);
            var files = new List<string>();
            for (var index = 1; index < args.Length; index += 2)
            {
                if (index + 1 >= args.Length || string.IsNullOrWhiteSpace(args[index + 1]))
                    throw new ArgumentException("Every option requires a nonempty value.");
                var option = args[index];
                if (option == "--file")
                    files.Add(args[index + 1]);
                else if (!options.TryAdd(option, args[index + 1]))
                    throw new ArgumentException("Duplicate option.");
            }

            var allowed = args[0] switch
            {
                "keygen" => new[] { "--private-key" },
                "public-key" => new[] { "--private-key", "--output" },
                "sign" or "sign-bundle" => new[] { "--private-key", "--release-id", "--output" },
                _ => throw new ArgumentException("Unknown command."),
            };
            if (options.Count != allowed.Length || allowed.Any(name => !options.ContainsKey(name))
                || (args[0] is not ("sign" or "sign-bundle") && files.Count != 0))
                throw new ArgumentException("Missing or unsupported option.");

            switch (args[0])
            {
                case "keygen":
                    ReleaseSigning.GeneratePrivateKey(options["--private-key"]);
                    break;
                case "public-key":
                    ReleaseSigning.ExportPublicKey(options["--private-key"], options["--output"]);
                    break;
                case "sign":
                    ReleaseSigning.SignManifest(options["--private-key"], options["--release-id"], files, options["--output"]);
                    break;
                case "sign-bundle":
                    ReleaseSigning.SignBundleManifest(options["--private-key"], options["--release-id"], files, options["--output"]);
                    break;
            }
            Console.WriteLine("Release signing command completed.");
            return 0;
        }
        catch (Exception error) when (error is ArgumentException or IOException or UnauthorizedAccessException
            or System.Security.Cryptography.CryptographicException or NotSupportedException)
        {
            // Never echo key input, command arguments, or provider exception data.
            Console.Error.WriteLine($"Release signing command failed ({error.GetType().Name}). Check the command, P-256 private key, file permissions, and new output paths.");
            return 1;
        }
    }
}
