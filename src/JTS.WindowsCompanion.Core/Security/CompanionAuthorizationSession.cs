using System.Security.Cryptography;
using JTS.WindowsCompanion.Protocol;

namespace JTS.WindowsCompanion.Security;

public readonly record struct CompanionAuthorizationDecision(
    bool Allowed,
    bool BootstrapMethod,
    string? AuthorizationScope);

public interface ICompanionAuthorizationGate
{
    bool IsAuthorized { get; }

    CompanionAuthorizationDecision Evaluate(string method);

    void ResetSession();
}

public sealed record CompanionAuthorizationChallenge(
    string ChallengeBase64,
    long ExpiresAtUnixMilliseconds,
    bool PairingRequired);

public sealed record CompanionAuthorizationResult(
    bool Authorized,
    bool NewlyPaired,
    Guid ClientDeviceId,
    string ClientFingerprintSha256,
    ulong StateRevision,
    string AuthorizationSource = "interactive",
    Guid? DelegationGrantId = null);

/// A read-only snapshot of the peer identity bound to the current live,
/// frame-authenticated session. The opaque owner key is derived locally from
/// the verified peer public key and live session binding; it is never accepted
/// from a request payload and is not a bearer credential.
public sealed record CompanionAuthorizedPeerContext(
    Guid DeviceId,
    string FingerprintSha256,
    string PublicKeyBase64,
    string OperationOwnerKey);

public interface ICompanionAuthorizedPeerContextSource
{
    bool TryGetAuthorizedPeerContext(out CompanionAuthorizedPeerContext? context);
}

public sealed class CompanionAuthorizationSession :
    ICompanionAuthorizationGate,
    ICompanionFrameAuthenticationContextSource,
    ICompanionAuthorizedPeerContextSource
{
    public const int ChallengeBytes = 32;
    public static readonly TimeSpan ChallengeLifetime = TimeSpan.FromMinutes(2);

    private static readonly HashSet<string> BootstrapMethods = new(StringComparer.Ordinal)
    {
        "companion.hello",
        "companion.authorize",
        "companion.state",
    };

    private readonly ICompanionIdentity _windowsIdentity;
    private readonly ICompanionPeerStore _peerStore;
    private readonly ICompanionPairingConsentPrompt _consentPrompt;
    private readonly Func<DateTimeOffset> _utcNow;
    private readonly CompanionSensitiveInteractionCoordinator _sensitiveInteractions;
    private readonly SemaphoreSlim _operationGate = new(1, 1);
    private readonly object _sync = new();
    private PendingChallenge? _pendingChallenge;
    private CompanionPeerIdentity? _authorizedPeer;
    private CompanionFrameAuthenticationContext? _frameAuthenticationContext;
    private bool _hasPersistedPeer;
    private ulong _stateRevision = 1;
    private ulong _handshakeGeneration;

    public CompanionAuthorizationSession(
        ICompanionIdentity windowsIdentity,
        ICompanionPeerStore peerStore,
        ICompanionPairingConsentPrompt consentPrompt,
        Func<DateTimeOffset>? utcNow = null,
        CompanionSensitiveInteractionCoordinator? sensitiveInteractions = null)
    {
        _windowsIdentity = windowsIdentity ?? throw new ArgumentNullException(nameof(windowsIdentity));
        _peerStore = peerStore ?? throw new ArgumentNullException(nameof(peerStore));
        _consentPrompt = consentPrompt ?? throw new ArgumentNullException(nameof(consentPrompt));
        _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
        _sensitiveInteractions = sensitiveInteractions ?? new CompanionSensitiveInteractionCoordinator();
    }

    public bool IsAuthorized
    {
        get
        {
            lock (_sync)
            {
                return _authorizedPeer is not null;
            }
        }
    }

    public bool HasPersistedPeer
    {
        get
        {
            lock (_sync)
            {
                return _hasPersistedPeer;
            }
        }
    }

    public ulong StateRevision
    {
        get
        {
            lock (_sync)
            {
                return _stateRevision;
            }
        }
    }

    public async ValueTask<CompanionAuthorizationChallenge> BeginHandshakeAsync(
        CancellationToken cancellationToken)
    {
        var helloChallenge = RandomNumberGenerator.GetBytes(ChallengeBytes);
        try
        {
            return await BeginHandshakeAsync(helloChallenge, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(helloChallenge);
        }
    }

    public async ValueTask<CompanionAuthorizationChallenge> BeginHandshakeAsync(
        ReadOnlyMemory<byte> helloChallenge,
        CancellationToken cancellationToken)
    {
        if (helloChallenge.Length != ChallengeBytes)
        {
            throw new CompanionProtocolException(
                "PAIRING_CHALLENGE_INVALID",
                "The hello challenge must be exactly 32 bytes for frame authentication.");
        }

        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_sync)
            {
                if (_authorizedPeer is not null)
                {
                    throw new CompanionProtocolException(
                        "PAIRING_ALREADY_AUTHORIZED",
                        "Disconnect or explicitly unpair before starting another Companion handshake.");
                }
            }
            var persistedPeer = await _peerStore.LoadAsync(cancellationToken).ConfigureAwait(false);
            var challenge = RandomNumberGenerator.GetBytes(ChallengeBytes);
            var now = _utcNow();
            lock (_sync)
            {
                ClearPendingChallenge();
                _authorizedPeer = null;
                _frameAuthenticationContext = null;
                _hasPersistedPeer = persistedPeer is not null;
                IncrementHandshakeGeneration();
                _pendingChallenge = new PendingChallenge(
                    challenge,
                    helloChallenge.ToArray(),
                    now,
                    _handshakeGeneration);
                IncrementRevision();
            }

            return new CompanionAuthorizationChallenge(
                Convert.ToBase64String(challenge),
                (now + ChallengeLifetime).ToUnixTimeMilliseconds(),
                PairingRequired: persistedPeer is null);
        }
        finally
        {
            _operationGate.Release();
        }
    }

    public async ValueTask<CompanionAuthorizationResult> AuthorizeAsync(
        ClientAuthorizationProof proof,
        CancellationToken cancellationToken)
    {
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            PendingChallenge pending;
            lock (_sync)
            {
                pending = _pendingChallenge
                    ?? throw new CompanionProtocolException(
                        "PAIRING_HELLO_REQUIRED",
                        "A fresh companion.hello challenge is required.");
                _pendingChallenge = null;
            }

            try
            {
                var now = _utcNow();
                if (now < pending.IssuedAtUtc || now - pending.IssuedAtUtc > ChallengeLifetime)
                {
                    throw new CompanionProtocolException(
                        "PAIRING_CHALLENGE_EXPIRED",
                        "The client authorization challenge has expired.");
                }

                var windowsMetadata = await _windowsIdentity.GetMetadataAsync(cancellationToken).ConfigureAwait(false);
                var peer = ClientAuthorizationProofService.Validate(
                    proof,
                    windowsMetadata.DeviceId,
                    pending.Bytes,
                    ChallengeLifetime,
                    now);
                EnsureCurrentHandshake(pending.Generation);
                var persistedGrant = await _peerStore.LoadAsync(cancellationToken).ConfigureAwait(false);
                var newlyPaired = false;
                if (persistedGrant is null)
                {
                    using var interaction = _sensitiveInteractions.Enter(
                        CompanionSensitiveInteractionKind.Pairing);
                    if (!await _consentPrompt.ConfirmAsync(peer, cancellationToken).ConfigureAwait(false))
                    {
                        throw new CompanionProtocolException(
                            "PAIRING_DECLINED",
                            "The Windows user declined the client pairing request.");
                    }

                    EnsureCurrentHandshake(pending.Generation);
                    await _peerStore.SaveIfAbsentAsync(
                        new CompanionPeerGrant(peer, now),
                        cancellationToken).ConfigureAwait(false);
                    persistedGrant = await _peerStore.LoadAsync(cancellationToken).ConfigureAwait(false)
                        ?? throw new CompanionProtocolException(
                            "PAIRING_PERSISTENCE_FAILED",
                            "The approved client identity could not be persisted.");
                    newlyPaired = true;
                }

                if (!CompanionPeerIdentityValidation.Matches(persistedGrant.Identity, peer))
                {
                    throw new CompanionProtocolException(
                        "PAIRING_IDENTITY_MISMATCH",
                        "This Windows Companion is paired with a different client identity.");
                }

                if (persistedGrant.ConsentReceipt is { } receipt &&
                    (receipt.ExpectedWindows.DeviceId != windowsMetadata.DeviceId ||
                     !string.Equals(receipt.ExpectedWindows.FingerprintSha256, windowsMetadata.FingerprintSha256, StringComparison.OrdinalIgnoreCase)))
                {
                    throw new CompanionProtocolException(
                        "DELEGATED_ENROLLMENT_WINDOWS_MISMATCH",
                        "The stored delegation belongs to a different Windows identity.");
                }

                var frameAuthenticationContext = CreateFrameAuthenticationContext(
                    windowsMetadata.DeviceId,
                    peer,
                    pending.HelloChallenge,
                    pending.Bytes);

                ulong revision;
                lock (_sync)
                {
                    EnsureCurrentHandshakeLocked(pending.Generation);
                    _authorizedPeer = peer;
                    _frameAuthenticationContext = frameAuthenticationContext;
                    _hasPersistedPeer = true;
                    IncrementRevision();
                    revision = _stateRevision;
                }

                return new CompanionAuthorizationResult(
                    Authorized: true,
                    newlyPaired,
                    peer.DeviceId,
                    peer.FingerprintSha256,
                    revision,
                    persistedGrant.ConsentReceipt?.AuthorizationSource ?? "interactive",
                    persistedGrant.ConsentReceipt?.GrantId);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pending.Bytes);
                CryptographicOperations.ZeroMemory(pending.HelloChallenge);
            }
        }
        finally
        {
            _operationGate.Release();
        }
    }

    public async ValueTask RevokeAsync(CancellationToken cancellationToken)
    {
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!IsAuthorized)
            {
                throw new CompanionProtocolException(
                    "PAIRING_REQUIRED",
                    "Client authorization is required for this Companion method.");
            }

            await _peerStore.ClearAsync(cancellationToken).ConfigureAwait(false);
            lock (_sync)
            {
                ClearPendingChallenge();
                _authorizedPeer = null;
                _frameAuthenticationContext = null;
                _hasPersistedPeer = false;
                IncrementHandshakeGeneration();
                IncrementRevision();
            }
        }
        finally
        {
            _operationGate.Release();
        }
    }

    public CompanionAuthorizationDecision Evaluate(string method)
    {
        var bootstrap = BootstrapMethods.Contains(method);
        lock (_sync)
        {
            if (bootstrap)
            {
                return new CompanionAuthorizationDecision(true, true, null);
            }

            return _authorizedPeer is null
                ? new CompanionAuthorizationDecision(false, false, null)
                : new CompanionAuthorizationDecision(
                    true,
                    false,
                    _authorizedPeer.FingerprintSha256);
        }
    }

    public void ResetSession()
    {
        lock (_sync)
        {
            var changed = _pendingChallenge is not null || _authorizedPeer is not null;
            ClearPendingChallenge();
            _authorizedPeer = null;
            _frameAuthenticationContext = null;
            IncrementHandshakeGeneration();
            if (changed)
            {
                IncrementRevision();
            }
        }
    }

    public bool TryGetFrameAuthenticationContext(
        out CompanionFrameAuthenticationContext? context)
    {
        lock (_sync)
        {
            context = _frameAuthenticationContext;
            return context is not null;
        }
    }

    public bool TryGetAuthorizedPeerContext(
        out CompanionAuthorizedPeerContext? context)
    {
        lock (_sync)
        {
            if (_authorizedPeer is null || _frameAuthenticationContext is null)
            {
                context = null;
                return false;
            }

            context = new CompanionAuthorizedPeerContext(
                _authorizedPeer.DeviceId,
                _authorizedPeer.FingerprintSha256,
                _authorizedPeer.PublicKeyBase64,
                _frameAuthenticationContext.DeriveOperationOwnerKey());
            return true;
        }
    }

    private void ClearPendingChallenge()
    {
        if (_pendingChallenge is not null)
        {
            CryptographicOperations.ZeroMemory(_pendingChallenge.Bytes);
            CryptographicOperations.ZeroMemory(_pendingChallenge.HelloChallenge);
            _pendingChallenge = null;
        }
    }

    private void IncrementRevision()
    {
        _stateRevision = _stateRevision == ulong.MaxValue ? 1 : _stateRevision + 1;
    }

    private void EnsureCurrentHandshake(ulong generation)
    {
        lock (_sync)
        {
            EnsureCurrentHandshakeLocked(generation);
        }
    }

    private void EnsureCurrentHandshakeLocked(ulong generation)
    {
        if (_handshakeGeneration != generation)
        {
            throw new CompanionProtocolException(
                "PAIRING_CHALLENGE_SUPERSEDED",
                "The client authorization challenge is no longer active.");
        }
    }

    private void IncrementHandshakeGeneration()
    {
        _handshakeGeneration = _handshakeGeneration == ulong.MaxValue ? 1 : _handshakeGeneration + 1;
    }

    private static CompanionFrameAuthenticationContext CreateFrameAuthenticationContext(
        Guid windowsDeviceId,
        CompanionPeerIdentity peer,
        ReadOnlySpan<byte> helloChallenge,
        ReadOnlySpan<byte> authorizationChallenge)
    {
        var binding = CompanionFrameAuthenticator.DeriveSessionBinding(
            windowsDeviceId,
            peer.DeviceId,
            helloChallenge,
            authorizationChallenge);
        byte[] publicKey;
        try
        {
            publicKey = Convert.FromBase64String(peer.PublicKeyBase64);
        }
        catch (FormatException)
        {
            CryptographicOperations.ZeroMemory(binding);
            throw new CompanionProtocolException(
                "FRAME_AUTH_CONTEXT_INVALID",
                "The authorized client public key is invalid.");
        }

        try
        {
            return new CompanionFrameAuthenticationContext(binding, publicKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(binding);
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    private sealed record PendingChallenge(
        byte[] Bytes,
        byte[] HelloChallenge,
        DateTimeOffset IssuedAtUtc,
        ulong Generation);
}
