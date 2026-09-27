using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.Windows.Security;

public sealed record CompanionPeerEnrollmentResult(bool Created, CompanionPeerGrant Grant);

public sealed class DpapiCompanionPeerStore : ICompanionPeerStore, IDisposable
{
    private static readonly byte[] Entropy = SHA256.HashData(Encoding.UTF8.GetBytes("JTS.WindowsCompanion.PairedPeer.v1"));
    private const int MaximumRevocations = 1024;
    private readonly string _storePath;
    private readonly IDataProtector _protector;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private bool _disposed;

    public DpapiCompanionPeerStore(string storePath, IDataProtector? protector = null)
    {
        if (string.IsNullOrWhiteSpace(storePath)) throw new ArgumentException("A paired-peer store path is required.", nameof(storePath));
        _storePath = Path.GetFullPath(storePath);
        _protector = protector ?? new DpapiDataProtector();
    }

    public async ValueTask<CompanionPeerGrant?> LoadAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { return (await LoadStateAsync(cancellationToken).ConfigureAwait(false)).Grant; }
        finally { _gate.Release(); }
    }

    public async ValueTask SaveIfAbsentAsync(CompanionPeerGrant grant, CancellationToken cancellationToken) =>
        _ = await SaveAsync(grant, delegated: false, cancellationToken).ConfigureAwait(false);

    public ValueTask<CompanionPeerEnrollmentResult> EnrollDelegatedAsync(CompanionPeerGrant grant, CancellationToken cancellationToken) =>
        SaveAsync(grant, delegated: true, cancellationToken);

    public async ValueTask ValidateEnrollmentAsync(CompanionPeerGrant grant, CancellationToken cancellationToken)
    {
        grant = NormalizeGrant(grant);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { RequireEnrollmentAllowed(await LoadStateAsync(cancellationToken).ConfigureAwait(false), grant); }
        finally { _gate.Release(); }
    }

    private async ValueTask<CompanionPeerEnrollmentResult> SaveAsync(CompanionPeerGrant grant, bool delegated, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        grant = NormalizeGrant(grant);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var lease = await AcquireWriteLeaseAsync(cancellationToken).ConfigureAwait(false);
            var state = await LoadStateAsync(cancellationToken).ConfigureAwait(false);
            if (delegated) RequireEnrollmentAllowed(state, grant);
            if (state.Grant is { } existing)
            {
                RequireMatchingPeer(existing.Identity, grant.Identity);
                return new CompanionPeerEnrollmentResult(false, existing);
            }
            await WriteStateAsync(state with { Grant = grant }, cancellationToken).ConfigureAwait(false);
            return new CompanionPeerEnrollmentResult(true, grant);
        }
        finally { _gate.Release(); }
    }

    public ValueTask ClearAsync(CancellationToken cancellationToken) => ClearCoreAsync(null, cancellationToken);

    public ValueTask RevokeDelegatedAsync(Guid grantId, CancellationToken cancellationToken)
    {
        if (grantId == Guid.Empty) throw new ArgumentException("A nonempty delegation grant ID is required.", nameof(grantId));
        return ClearCoreAsync(grantId, cancellationToken);
    }

    public async ValueTask ValidateRevocationAsync(Guid grantId, CancellationToken cancellationToken)
    {
        var grant = await LoadAsync(cancellationToken).ConfigureAwait(false);
        RequireRevocationMatches(grant, grantId);
    }

    private async ValueTask ClearCoreAsync(Guid? expectedGrantId, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var lease = await AcquireWriteLeaseAsync(cancellationToken).ConfigureAwait(false);
            var state = await LoadStateAsync(cancellationToken).ConfigureAwait(false);
            if (expectedGrantId is { } id) RequireRevocationMatches(state.Grant, id);
            if (state.Grant?.ConsentReceipt is { } receipt)
            {
                var revoked = state.RevokedGrantIds.Append(receipt.GrantId).Distinct().ToArray();
                state = state with { RevokedGrantIds = revoked, LastRevocation = new Revocation(receipt, DateTimeOffset.UtcNow) };
            }
            // Revocation and its receipt are one atomic protected replacement. A
            // concurrent offline enrollment cannot resurrect the revoked grant.
            await WriteStateAsync(state with { Grant = null }, cancellationToken).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    private static void RequireRevocationMatches(CompanionPeerGrant? grant, Guid id)
    {
        if (grant?.ConsentReceipt?.GrantId != id)
            throw new CompanionProtocolException("DELEGATION_GRANT_MISMATCH", "The requested delegation is not the current grant.");
    }

    private static void RequireEnrollmentAllowed(StoredPeerState state, CompanionPeerGrant grant)
    {
        var receipt = grant.ConsentReceipt ?? throw new ArgumentException("Delegated enrollment requires an explicit receipt.");
        if (state.RevokedGrantIds.Contains(receipt.GrantId))
            throw new CompanionProtocolException("DELEGATION_REVOKED", "This delegation was revoked. A new owner-authorized grant is required.");
        if (state.Grant is { } existing)
        {
            RequireMatchingPeer(existing.Identity, grant.Identity);
            if (existing.ConsentReceipt?.GrantId != receipt.GrantId ||
                existing.ConsentReceipt.RequestSha256 != receipt.RequestSha256)
                throw new CompanionProtocolException("DELEGATION_GRANT_CONFLICT", "Revoke the existing grant before changing its delegation.");
        }
        else if (state.RevokedGrantIds.Length >= MaximumRevocations)
            throw new CompanionProtocolException("DELEGATION_HISTORY_FULL", "The current-user delegation history has reached its supported limit.");
    }

    private async ValueTask<StoredPeerState> LoadStateAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_storePath)) return new StoredPeerState(null, [], null);
        byte[] protectedBytes = [], plaintext = [];
        try
        {
            RejectLink(_storePath);
            await using var stream = new FileStream(_storePath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 4096, FileOptions.Asynchronous);
            if (stream.Length > 256 * 1024) throw new CryptographicException("The paired-peer store is too large.");
            var envelope = await JsonSerializer.DeserializeAsync<StoredPeerEnvelope>(stream, ControlMessageSerializer.Options, cancellationToken).ConfigureAwait(false)
                ?? throw new CryptographicException("The paired-peer store is empty.");
            if (envelope.Version is not (1 or 2) || string.IsNullOrWhiteSpace(envelope.ProtectedGrantBase64) || envelope.ProtectedGrantBase64.Length > 200 * 1024)
                throw new CryptographicException("The paired-peer store format is invalid.");
            protectedBytes = Convert.FromBase64String(envelope.ProtectedGrantBase64);
            plaintext = _protector.Unprotect(protectedBytes, Entropy);
            var state = envelope.Version == 1
                ? new StoredPeerState(JsonSerializer.Deserialize<CompanionPeerGrant>(plaintext, ControlMessageSerializer.Options)
                    ?? throw new CryptographicException("The protected paired-peer grant is empty."), [], null)
                : JsonSerializer.Deserialize<StoredPeerState>(plaintext, ControlMessageSerializer.Options)
                    ?? throw new CryptographicException("The protected paired-peer state is empty.");
            if (state.RevokedGrantIds is null || state.RevokedGrantIds.Length > MaximumRevocations || state.RevokedGrantIds.Any(id => id == Guid.Empty) ||
                state.RevokedGrantIds.Distinct().Count() != state.RevokedGrantIds.Length)
                throw new CryptographicException("The protected revocation history is invalid.");
            if (state.LastRevocation is { } revoked)
            {
                var normalized = CompanionDelegatedEnrollmentValidation.NormalizeReceipt(revoked.Receipt, revoked.Receipt.MacIdentity);
                if (!state.RevokedGrantIds.Contains(normalized.GrantId)) throw new CryptographicException("The revocation receipt is inconsistent.");
            }
            var grant = state.Grant is null ? null : NormalizeGrant(state.Grant);
            if (grant?.ConsentReceipt is { } receipt && state.RevokedGrantIds.Contains(receipt.GrantId))
                throw new CryptographicException("A revoked grant cannot remain active.");
            return state with { Grant = grant };
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException or JsonException or CompanionProtocolException)
        { throw new CryptographicException("The paired-peer store is invalid.", exception); }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private async ValueTask WriteStateAsync(StoredPeerState state, CancellationToken cancellationToken)
    {
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(state, ControlMessageSerializer.Options);
        byte[] protectedBytes = [];
        var temporaryPath = _storePath + $".{Guid.NewGuid():N}.tmp";
        try
        {
            protectedBytes = _protector.Protect(plaintext, Entropy);
            var envelope = new StoredPeerEnvelope(2, Convert.ToBase64String(protectedBytes));
            await File.WriteAllTextAsync(temporaryPath, JsonSerializer.Serialize(envelope, ControlMessageSerializer.Options), Encoding.UTF8, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            RejectLink(_storePath);
            File.Move(temporaryPath, _storePath, overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(protectedBytes);
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    private async ValueTask<FileStream> AcquireWriteLeaseAsync(CancellationToken cancellationToken)
    {
        var parent = Path.GetDirectoryName(_storePath) ?? throw new InvalidOperationException("The peer store has no parent directory.");
        Directory.CreateDirectory(parent);
        RejectLink(parent);
        var path = _storePath + ".lock";
        var wait = Stopwatch.StartNew();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RejectLink(path);
            try { return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.None); }
            catch (IOException) when (wait.Elapsed < TimeSpan.FromSeconds(30))
            { await Task.Delay(25, cancellationToken).ConfigureAwait(false); }
        }
    }

    private static CompanionPeerGrant NormalizeGrant(CompanionPeerGrant grant)
    {
        ArgumentNullException.ThrowIfNull(grant);
        var identity = CompanionPeerIdentityValidation.Normalize(grant.Identity);
        var receipt = grant.ConsentReceipt is null ? null : CompanionDelegatedEnrollmentValidation.NormalizeReceipt(grant.ConsentReceipt, identity);
        if (receipt is not null && receipt.ApprovedAtUtc != grant.ApprovedAtUtc)
            throw new CryptographicException("The grant approval and consent receipt differ.");
        return grant with { Identity = identity, ConsentReceipt = receipt };
    }

    private static void RejectLink(string path)
    {
        if ((File.Exists(path) || Directory.Exists(path)) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Companion peer storage cannot use a reparse point.");
    }

    private static void RequireMatchingPeer(CompanionPeerIdentity existing, CompanionPeerIdentity requested)
    {
        if (!CompanionPeerIdentityValidation.Matches(existing, requested))
            throw new CompanionProtocolException("PAIRING_IDENTITY_MISMATCH", "This Windows Companion is paired with a different client identity.");
    }

    public void Dispose()
    {
        if (_disposed) return;
        _gate.Dispose();
        _disposed = true;
    }

    private sealed record StoredPeerEnvelope(int Version, string ProtectedGrantBase64);
    private sealed record StoredPeerState(CompanionPeerGrant? Grant, Guid[] RevokedGrantIds, Revocation? LastRevocation);
    private sealed record Revocation(CompanionDelegatedConsentReceipt Receipt, DateTimeOffset RevokedAtUtc);
}
