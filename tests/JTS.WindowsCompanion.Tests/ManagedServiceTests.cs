using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Elevation;
using JTS.WindowsCompanion.Managed;
using JTS.WindowsCompanion.Protocol;

namespace JTS.WindowsCompanion.Tests;

public sealed class ManagedServiceTests
{
    [Fact]
    public void InstalledStore_LoadsOnlyHashPinnedRelativeHandlerAndFixedOperations()
    {
        using var temporary = new TemporaryDirectory();
        var manifests = Directory.CreateDirectory(Path.Combine(temporary.Path, "manifests")).FullName;
        var handlers = Directory.CreateDirectory(Path.Combine(temporary.Path, "handlers")).FullName;
        var handler = Path.Combine(handlers, "vrc-handler.exe");
        File.WriteAllText(handler, "fixed-handler");
        var digest = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(handler)));
        File.WriteAllText(Path.Combine(manifests, "vrc-factory.json"), JsonSerializer.Serialize(new
        {
            providerId = "vrc-factory",
            version = "1.0.0",
            handlerExecutable = "vrc-handler.exe",
            handlerSha256 = digest,
            operations = new[]
            {
                new
                {
                    operationId = "clean-install-auto",
                    acceptedArguments = new[] { "jobId", "packagePath" },
                    allowedRootIds = new[] { "factory" },
                    maximumDurationMilliseconds = 30 * 60 * 1000,
                },
            },
        }, ControlMessageSerializer.Options));

        var store = new InstalledManagedProviderStore(manifests, handlers);
        Assert.Equal(handler, store.Get("vrc-factory").HandlerExecutablePath);

        File.WriteAllText(Path.Combine(manifests, "unsafe.json"), JsonSerializer.Serialize(new
        {
            providerId = "unsafe",
            version = "1.0.0",
            handlerExecutable = "vrc-handler.exe",
            handlerSha256 = digest,
            operations = new[]
            {
                new
                {
                    operationId = "run-tool",
                    acceptedArguments = new[] { "script" },
                    allowedRootIds = Array.Empty<string>(),
                    maximumDurationMilliseconds = 1_000,
                },
            },
        }, ControlMessageSerializer.Options));
        Assert.Throws<ArgumentException>(() => new InstalledManagedProviderStore(manifests, handlers));
    }

    [Fact]
    public async Task Dispatcher_RejectsUninstalledShellWithoutCallingHandler()
    {
        using var temporary = new TemporaryDirectory();
        var manifests = Directory.CreateDirectory(Path.Combine(temporary.Path, "manifests")).FullName;
        var handlers = Directory.CreateDirectory(Path.Combine(temporary.Path, "handlers")).FullName;
        var handler = Path.Combine(handlers, "fixed.exe");
        File.WriteAllText(handler, "fixed");
        var digest = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(handler)));
        File.WriteAllText(Path.Combine(manifests, "fixed.json"), JsonSerializer.Serialize(new
        {
            providerId = "fixed",
            version = "1.0.0",
            handlerExecutable = "fixed.exe",
            handlerSha256 = digest,
            operations = new[]
            {
                new
                {
                    operationId = "doctor",
                    acceptedArguments = Array.Empty<string>(),
                    allowedRootIds = Array.Empty<string>(),
                    maximumDurationMilliseconds = 1_000,
                },
            },
        }, ControlMessageSerializer.Options));
        var executor = new RecordingExecutor();
        var dispatcher = new ManagedServiceDispatcher(
            new InstalledManagedProviderStore(manifests, handlers),
            executor);
        var request = new ManagedServiceMessage(
            ManagedServiceDispatcher.ProtocolVersion,
            Guid.NewGuid(),
            ManagedServiceMessageKind.Execute,
            ControlMessageSerializer.ToElement(new ManagedOperationRequest(
                "fixed",
                "shell.exec",
                new Dictionary<string, string> { ["script"] = "whoami" },
                new HashSet<string>(),
                TimeSpan.FromSeconds(1))));
        await using var stream = new ScriptedDuplexStream(
            JsonSerializer.SerializeToUtf8Bytes(request, ControlMessageSerializer.Options));
        await dispatcher.HandleOneAsync(stream, CancellationToken.None);
        var response = stream.ReadWritten<ManagedServiceMessage>();
        Assert.Equal(ManagedServiceMessageKind.Error, response.Kind);
        Assert.False(executor.Called);
    }

    private sealed class RecordingExecutor : IManagedOperationExecutor
    {
        public bool Called { get; private set; }

        public ValueTask<ManagedOperationExecutionResult> ExecuteAsync(
            InstalledManagedProvider provider,
            AuthorizedManagedOperation operation,
            CancellationToken cancellationToken)
        {
            Called = true;
            return ValueTask.FromResult(new ManagedOperationExecutionResult(0, string.Empty, string.Empty, false, false, 0));
        }
    }

    private sealed class ScriptedDuplexStream : Stream
    {
        private readonly MemoryStream _read;
        private readonly MemoryStream _written = new();

        public ScriptedDuplexStream(byte[] requestPayload)
        {
            _read = new MemoryStream();
            LocalIpcJsonCodec.WriteAsync(
                _read,
                JsonSerializer.Deserialize<ManagedServiceMessage>(requestPayload, ControlMessageSerializer.Options)!,
                CancellationToken.None).AsTask().GetAwaiter().GetResult();
            _read.Position = 0;
        }

        public T ReadWritten<T>()
        {
            _written.Position = 0;
            return LocalIpcJsonCodec.ReadAsync<T>(_written, CancellationToken.None).AsTask().GetAwaiter().GetResult();
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => _written.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) => _written.FlushAsync(cancellationToken);
        public override int Read(byte[] buffer, int offset, int count) => _read.Read(buffer, offset, count);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            _read.ReadAsync(buffer, cancellationToken);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => _written.Write(buffer, offset, count);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            _written.WriteAsync(buffer, cancellationToken);
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _read.Dispose();
                _written.Dispose();
            }

            base.Dispose(disposing);
        }
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"jts-managed-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
