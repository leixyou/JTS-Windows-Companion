using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using JTS.WindowsCompanion.Relay;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.Control.Tests;

internal sealed class ControlFixture : IAsyncDisposable, IControlGrantProvider, IJobExecutor
{
    private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("jts-control-test-");
    private readonly X509Certificate2 _server = Certificate(), _client = Certificate();
    internal RelayEndpointIdentity ServerIdentity { get; }
    internal RelayEndpointIdentity ClientIdentity { get; }
    internal Guid GrantId { get; } = Guid.NewGuid();
    internal ControlGrant? Grant { get; set; }
    internal DurableJobStore Store { get; }
    internal CompanionControlHost Host { get; }
    internal DurableControlGrantStore? DurableGrants { get; }
    internal int Executions;
    internal TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal ConcurrentQueue<Exception> SessionErrors { get; } = new();
    private readonly List<Task> _sessions = [];
    private readonly FixtureProtector _protector = new();

    internal ControlFixture(bool durableGrants = false, Func<DurableControlGrantStore, IControlGrantProvider>? decorate = null)
    {
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(_directory.FullName, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        ServerIdentity = new(_server); ClientIdentity = new(_client);
        Grant = new(ClientIdentity.DeviceId, GrantId, DateTimeOffset.UtcNow.AddHours(25), Enum.GetValues<ControlOperation>(), ["fixture.echo", "fixture.block"], true);
        Store = DurableJobStore.CreateNew(Path.Combine(_directory.FullName, "jobs.sqlite"), _protector);
        if (durableGrants)
        {
            DurableGrants = DurableControlGrantStore.CreateNew(Path.Combine(_directory.FullName, "grants.sqlite"), _protector);
            DurableGrants.ApproveLocally(Grant);
        }
        Host = new(Store, DurableGrants is null ? this : decorate?.Invoke(DurableGrants) ?? DurableGrants, this);
    }

    public ValueTask<ControlGrant?> FindAsync(string owner, Guid grant, CancellationToken token)
        => ValueTask.FromResult(Grant?.OwnerDeviceId == owner && Grant.GrantId == grant ? Grant : null);

    public async ValueTask<JobExecutionResult> ExecuteAsync(JobBinding binding, ReadOnlyMemory<byte> payload, IJobOutputSink output, CancellationToken token)
    {
        Interlocked.Increment(ref Executions); Started.TrySetResult();
        if (binding.Kind == "fixture.block") await Release.Task.WaitAsync(token);
        await output.AppendAsync(payload, token);
        return new(true, "OK");
    }

    internal async Task<ControlTestClient> ConnectAsync(RelayLane lane = RelayLane.Control)
    {
        var policy = OperatingSystem.IsMacOS() ? RelayTlsPolicy.ExplicitWindows10Tls12 : RelayTlsPolicy.Tls13;
        var binding = new RelayBinding(Guid.NewGuid(), lane, ClientIdentity.DeviceId, ServerIdentity.DeviceId);
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        var client = new TcpClient(); await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
        var accepted = await listener.AcceptTcpClientAsync();
        Exception? serverFailure = null;
        var server = Task.Run(async () =>
        {
            try { await Host.ServeAsync(accepted.GetStream(), ServerIdentity, new(ClientIdentity.DeviceId, policy, [lane]), binding); }
            catch (Exception error) { serverFailure = error; SessionErrors.Enqueue(error); }
            finally { accepted.Dispose(); }
        });
        _sessions.Add(server);
        try
        {
            var tls = await RelaySecureStream.AuthenticateAsync(client.GetStream(), ClientIdentity,
                new(ServerIdentity.DeviceId, policy, [lane]), binding, true);
            return new(client, tls, server, GrantId);
        }
        catch (Exception clientError)
        {
            client.Dispose(); await server.WaitAsync(TimeSpan.FromSeconds(5));
            if (serverFailure is not null)
                throw new AggregateException("Control fixture connection failed at both endpoints.", clientError, serverFailure);
            throw;
        }
    }

    internal object Submission(Guid jobId, string kind = "fixture.echo", bool detached = false, DateTimeOffset? deadline = null, byte[]? payload = null)
        => new { jobId = jobId.ToString("D"), kind, deadlineUnixMilliseconds = (deadline ?? DateTimeOffset.UtcNow.AddMinutes(1)).ToUnixTimeMilliseconds(),
            allowDisconnected = detached, payloadBase64 = Convert.ToBase64String(payload ?? [1, 2, 3, 4]) };

    internal async Task<JobSnapshot> WaitForAsync(Guid id, DurableJobState state)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (true)
        {
            var snapshot = Store.Get(id, ClientIdentity.DeviceId, GrantId);
            if (snapshot.State == state) return snapshot;
            await Task.Delay(10, deadline.Token);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await Host.DisposeAsync(); await Task.WhenAll(_sessions).WaitAsync(TimeSpan.FromSeconds(5));
        Store.Dispose(); DurableGrants?.Dispose(); _protector.Dispose(); _client.Dispose(); _server.Dispose(); _directory.Delete(true);
    }
    internal static X509Certificate2 Certificate()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=JTS disposable control fixture", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        if (!OperatingSystem.IsWindows()) return certificate;
        // Like the enrolled identity loader, use a lifetime-scoped user key on
        // Windows: Schannel cannot use CreateSelfSigned's ephemeral private key.
        // No PersistKeySet or certificate-store registration is requested.
        using (certificate)
        {
            var pfx = certificate.Export(X509ContentType.Pkcs12);
            try
            {
                return X509CertificateLoader.LoadPkcs12(pfx, (string?)null, X509KeyStorageFlags.UserKeySet,
                    new Pkcs12LoaderLimits { MaxCertificates = 1, MaxKeys = 1 });
            }
            finally { CryptographicOperations.ZeroMemory(pfx); }
        }
    }
}

internal sealed class FixtureProtector : ITaskPayloadProtector, IDisposable
{
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    public byte[] Protect(ReadOnlySpan<byte> plain, ReadOnlySpan<byte> purpose)
    {
        var result = new byte[28 + plain.Length]; RandomNumberGenerator.Fill(result.AsSpan(0, 12));
        using var aes = new AesGcm(_key, 16); aes.Encrypt(result.AsSpan(0, 12), plain, result.AsSpan(28), result.AsSpan(12, 16), purpose); return result;
    }
    public byte[] Unprotect(ReadOnlySpan<byte> value, ReadOnlySpan<byte> purpose)
    {
        var result = new byte[value.Length - 28]; using var aes = new AesGcm(_key, 16);
        aes.Decrypt(value[..12], value[28..], value.Slice(12, 16), result, purpose); return result;
    }
    public void Dispose() => CryptographicOperations.ZeroMemory(_key);
}

internal sealed class ControlTestClient(TcpClient client, SslStream tls, Task server, Guid grantId) : IAsyncDisposable
{
    internal Stream Stream => tls;
    // TLS EOF precedes the server wrapper recording its terminal exception.
    internal Task WaitForServerCompletionAsync() => server.WaitAsync(TimeSpan.FromSeconds(5));
    internal async Task<JsonDocument> CallAsync(string operation, object parameters, Guid? grant = null)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var id = Guid.NewGuid().ToString("D");
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new { version = 1, id, operation, grantId = (grant ?? grantId).ToString("D"), parameters });
        await ControlWire.WriteAsync(tls, bytes, deadline.Token);
        var result = JsonDocument.Parse(await ControlWire.ReadAsync(tls, deadline.Token) ?? throw new IOException("closed"));
        if (result.RootElement.GetProperty("id").GetString() != id) throw new IOException("wrong_id");
        return result;
    }
    public async ValueTask DisposeAsync()
    { await tls.DisposeAsync(); client.Dispose(); await server.WaitAsync(TimeSpan.FromSeconds(5)); }
}
