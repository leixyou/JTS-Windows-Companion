using System.Collections.Concurrent;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Security;
using JTS.WindowsCompanion.Transport;
using JTS.WindowsCompanion.Transfers;

namespace JTS.WindowsCompanion.Agent;

public sealed class CompanionAgent
{
    private const int MaximumConcurrentOperations = 32;
    private const string CancelMethod = "companion.cancel";
    private const string CancelPendingMethod = "companion.cancelPending";

    private readonly ICompanionChannel _channel;
    private readonly CompanionRequestRouter _router;
    private readonly SequenceReplayGuard _replayGuard;
    private readonly ISecurityEventSink _events;
    private readonly BinaryTransferCoordinator? _transfers;
    private readonly CompanionFrameAuthenticator? _frameAuthenticator;
    private readonly CompanionOperationRegistry _operationRegistry;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private long _outboundSequence;
    private int _diagnosticFrames;

    public CompanionAgent(
        ICompanionChannel channel,
        CompanionRequestRouter router,
        SequenceReplayGuard? replayGuard = null,
        BinaryTransferCoordinator? transfers = null,
        ISecurityEventSink? events = null,
        CompanionFrameAuthenticator? frameAuthenticator = null,
        TimeProvider? timeProvider = null)
    {
        _channel = channel ?? throw new ArgumentNullException(nameof(channel));
        _router = router ?? throw new ArgumentNullException(nameof(router));
        _replayGuard = replayGuard ?? new SequenceReplayGuard();
        _transfers = transfers;
        _events = events ?? NullSecurityEventSink.Instance;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _operationRegistry = new CompanionOperationRegistry(_timeProvider);
        if (router.Authorization is ICompanionFrameAuthenticationContextSource
            && frameAuthenticator is null)
        {
            throw new ArgumentNullException(
                nameof(frameAuthenticator),
                "An authorization session with frame authentication requires an authenticator.");
        }

        _frameAuthenticator = frameAuthenticator;
        _transfers?.BindSender(SendBinaryAsync);
    }

    public Task RunAsync(CancellationToken cancellationToken) =>
        RunAsync(onConnected: null, cancellationToken);

    public async Task RunAsync(
        Func<CancellationToken, ValueTask>? onConnected,
        CancellationToken cancellationToken)
    {
        using var runtime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var operations = new ConcurrentDictionary<long, Task>();
        var backgroundFailure = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
        long operationSequence = 0;
        Task<CompanionFrame>? pendingReceive = null;
        _router.Authorization.ResetSession();
        try
        {
            await _channel.ConnectAsync(runtime.Token).ConfigureAwait(false);
            if (onConnected is not null)
            {
                await onConnected(runtime.Token).ConfigureAwait(false);
            }
            while (!runtime.IsCancellationRequested)
            {
                var receive = pendingReceive = _channel.ReceiveAsync(runtime.Token).AsTask();
                var completed = await Task.WhenAny(receive, backgroundFailure.Task).ConfigureAwait(false);
                if (completed == backgroundFailure.Task)
                {
                    throw await backgroundFailure.Task.ConfigureAwait(false);
                }

                var wireFrame = await receive.ConfigureAwait(false);
                pendingReceive = null;
                var authenticatedFrame = _frameAuthenticator?.AuthenticateInbound(wireFrame)
                    ?? new AuthenticatedCompanionFrame(wireFrame, null);
                var frame = authenticatedFrame.Frame;
                if (frame.Version != CompanionProtocol.CurrentVersion)
                {
                    throw new CompanionProtocolException("PROTOCOL_VERSION_UNSUPPORTED", "The protocol version is not supported.");
                }

                _replayGuard.Accept(frame.Sequence);
                switch (frame.Type)
                {
                    case CompanionFrameType.Ping:
                        await SendAsync(
                            CompanionFrameType.Pong,
                            ReadOnlyMemory<byte>.Empty,
                            authenticatedFrame.AuthenticationContext,
                            runtime.Token).ConfigureAwait(false);
                        break;
                    case CompanionFrameType.ControlJson:
                        {
                            var request = ControlMessageSerializer.Deserialize<CompanionRequest>(frame.Payload.Span);
                            if (operations.Count >= MaximumConcurrentOperations
                                && !BypassesConcurrencyLimit(request.Method))
                            {
                                await SendResponseAsync(
                                    request,
                                    CompanionResponse.Fail(
                                        request.RequestId,
                                        "COMPANION_BUSY",
                                        "The Windows Companion has reached its concurrent operation limit.",
                                        retryable: true),
                                    authenticatedFrame.AuthenticationContext,
                                    runtime.Token).ConfigureAwait(false);
                                break;
                            }

                            var operationId = Interlocked.Increment(ref operationSequence);
                            var operation = HandleControlAsync(
                                request,
                                authenticatedFrame.AuthenticationContext,
                                runtime.Token).AsTask();
                            operations[operationId] = operation;
                            _ = operation.ContinueWith(
                                completedOperation =>
                                {
                                    operations.TryRemove(operationId, out _);
                                    if (completedOperation.IsFaulted)
                                    {
                                        backgroundFailure.TrySetResult(
                                            completedOperation.Exception?.GetBaseException()
                                            ?? new InvalidOperationException("A companion request failed."));
                                    }
                                },
                                CancellationToken.None,
                                TaskContinuationOptions.ExecuteSynchronously,
                                TaskScheduler.Default);
                            break;
                        }
                    case CompanionFrameType.BinaryChunk:
                        if (!_router.Authorization.IsAuthorized)
                        {
                            throw new CompanionProtocolException(
                                "PAIRING_REQUIRED",
                                "Client authorization is required for binary Companion frames.");
                        }

                        if (_transfers is null)
                        {
                            throw new CompanionProtocolException("BINARY_HANDLER_REQUIRED", "No binary transfer handler is registered.");
                        }

                        await _transfers.AcceptUploadChunkAsync(
                            BinaryChunkCodec.Decode(frame.Payload.Span),
                            runtime.Token).ConfigureAwait(false);
                        break;
                    default:
                        throw new CompanionProtocolException("FRAME_TYPE_INVALID", "The frame type is not accepted from the client.");
                }
            }
        }
        finally
        {
            runtime.Cancel();
            if (pendingReceive is not null)
            {
                try { await pendingReceive.ConfigureAwait(false); }
                catch (Exception) when (runtime.IsCancellationRequested) { }
            }
            try
            {
                await _operationRegistry.CancelAllAndDrainAsync(CancellationToken.None)
                    .ConfigureAwait(false);
                await Task.WhenAll(operations.Values).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (runtime.IsCancellationRequested)
            {
            }
            catch (Exception) when (runtime.IsCancellationRequested)
            {
            }

            _router.Authorization.ResetSession();
        }

        cancellationToken.ThrowIfCancellationRequested();
    }

    private ValueTask SendBinaryAsync(BinaryChunk chunk, CancellationToken cancellationToken)
    {
        if (!_router.Authorization.IsAuthorized)
        {
            throw new CompanionProtocolException(
                "PAIRING_REQUIRED",
                "Client authorization is required for binary Companion frames.");
        }

        return SendAsync(
            CompanionFrameType.BinaryChunk,
            BinaryChunkCodec.Encode(chunk),
            authenticationContext: null,
            cancellationToken: cancellationToken);
    }

    private async ValueTask HandleControlAsync(
        CompanionRequest request,
        CompanionFrameAuthenticationContext? authenticationContext,
        CancellationToken cancellationToken)
    {
        var ownerKey = authenticationContext?.DeriveOperationOwnerKey();
        if (request.Method == CancelMethod)
        {
            var response = HandleCancel(request, authenticationContext, ownerKey);
            await SendResponseAsync(request, response, authenticationContext, cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        CompanionOperationRegistry.CompanionOperationLease? operation = null;
        if (ownerKey is not null && IsTrackedOperation(request.Method))
        {
            try
            {
                operation = _operationRegistry.Register(
                    request.RequestId,
                    ownerKey,
                    request.DeadlineUnixMilliseconds,
                    cancellationToken);
            }
            catch (CompanionProtocolException exception)
            {
                await SendResponseAsync(
                    request,
                    CompanionResponse.Fail(
                        request.RequestId,
                        exception.Code,
                        exception.Message),
                    authenticationContext,
                    cancellationToken).ConfigureAwait(false);
                return;
            }
        }

        using (operation)
        {
            var operationCancellationToken = operation?.CancellationToken ?? cancellationToken;
            CompanionResponse response;
            try
            {
                response = await DispatchOperationAsync(
                    request,
                    authenticationContext,
                    ownerKey,
                    operationCancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (operation?.CancellationToken.IsCancellationRequested == true)
            {
                response = CancellationResponse(request, operation.CancellationReason);
                if (operation.CancellationReason == CompanionOperationCancellationReason.ConnectionClosed)
                {
                    return;
                }
            }

            await SendResponseAsync(request, response, authenticationContext, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private async ValueTask<CompanionResponse> DispatchOperationAsync(
        CompanionRequest request,
        CompanionFrameAuthenticationContext? authenticationContext,
        string? ownerKey,
        CancellationToken cancellationToken)
    {
        if (request.Method == CancelPendingMethod)
        {
            return await HandleCancelPendingAsync(
                request,
                authenticationContext,
                ownerKey,
                cancellationToken).ConfigureAwait(false);
        }

        if (request.Method == "companion.unpair"
            && ValidateAuthenticatedControl(request, authenticationContext) is null
            && ownerKey is not null)
        {
            using var ownerBlock = await _operationRegistry.BlockOwnerAndDrainAsync(
                ownerKey,
                request.RequestId,
                cancellationToken).ConfigureAwait(false);
            return await _router.DispatchAsync(
                request,
                _timeProvider.GetUtcNow(),
                cancellationToken).ConfigureAwait(false);
        }

        return await _router.DispatchAsync(
            request,
            _timeProvider.GetUtcNow(),
            cancellationToken).ConfigureAwait(false);
    }

    private CompanionResponse HandleCancel(
        CompanionRequest request,
        CompanionFrameAuthenticationContext? authenticationContext,
        string? ownerKey)
    {
        var validationFailure = ValidateAuthenticatedControl(request, authenticationContext);
        if (validationFailure is not null)
        {
            return validationFailure;
        }

        if (ownerKey is null || !TryReadCancellationTarget(request, out var targetRequestId))
        {
            return CompanionResponse.Fail(
                request.RequestId,
                "REQUEST_INVALID",
                "A valid target request ID is required.");
        }

        return _operationRegistry.Cancel(ownerKey, targetRequestId)
            ? CompanionResponse.Ok(request.RequestId, new { cancelled = true })
            : CompanionResponse.Fail(
                request.RequestId,
                "REQUEST_NOT_ACTIVE",
                "The requested operation is not active for this authenticated session.");
    }

    private async ValueTask<CompanionResponse> HandleCancelPendingAsync(
        CompanionRequest request,
        CompanionFrameAuthenticationContext? authenticationContext,
        string? ownerKey,
        CancellationToken cancellationToken)
    {
        var validationFailure = ValidateAuthenticatedControl(request, authenticationContext);
        if (validationFailure is not null)
        {
            return validationFailure;
        }

        if (ownerKey is null)
        {
            return CompanionResponse.Fail(
                request.RequestId,
                "PAIRING_REQUIRED",
                "A frame-authenticated Companion session is required.");
        }

        var cancelled = await _operationRegistry.CancelOwnerAndDrainAsync(
            ownerKey,
            CompanionOperationCancellationReason.RequestCancelled,
            request.RequestId,
            cancellationToken).ConfigureAwait(false);
        return CompanionResponse.Ok(request.RequestId, new { cancelled });
    }

    private CompanionResponse? ValidateAuthenticatedControl(
        CompanionRequest request,
        CompanionFrameAuthenticationContext? authenticationContext)
    {
        if (request.ProtocolVersion != CompanionProtocol.CurrentVersion)
        {
            return CompanionResponse.Fail(
                request.RequestId,
                "PROTOCOL_VERSION_UNSUPPORTED",
                "The protocol version is not supported.");
        }

        if (request.RequestId == Guid.Empty)
        {
            return CompanionResponse.Fail(
                request.RequestId,
                "REQUEST_INVALID",
                "The request ID is required.");
        }

        if (request.DeadlineUnixMilliseconds is { } deadline
            && _timeProvider.GetUtcNow().ToUnixTimeMilliseconds() > deadline)
        {
            return CompanionResponse.Fail(
                request.RequestId,
                "DEADLINE_EXCEEDED",
                "The request deadline has elapsed.",
                retryable: true);
        }

        var authorization = _router.Authorization.Evaluate(request.Method);
        if (authenticationContext is null || !authorization.Allowed || authorization.BootstrapMethod)
        {
            return CompanionResponse.Fail(
                request.RequestId,
                "PAIRING_REQUIRED",
                "A frame-authenticated Companion session is required.");
        }

        return null;
    }

    private static CompanionResponse CancellationResponse(
        CompanionRequest request,
        CompanionOperationCancellationReason reason) => reason switch
        {
            CompanionOperationCancellationReason.DeadlineExceeded => CompanionResponse.Fail(
                request.RequestId,
                "DEADLINE_EXCEEDED",
                "The request deadline elapsed.",
                retryable: true),
            CompanionOperationCancellationReason.RequestCancelled
                or CompanionOperationCancellationReason.PeerUnpaired => CompanionResponse.Fail(
                    request.RequestId,
                    "REQUEST_CANCELLED",
                    "The request was cancelled.",
                    retryable: true),
            _ => CompanionResponse.Fail(
                request.RequestId,
                "REQUEST_CANCELLED",
                "The request was cancelled.",
                retryable: true),
        };

    private static bool TryReadCancellationTarget(
        CompanionRequest request,
        out Guid targetRequestId)
    {
        targetRequestId = Guid.Empty;
        return request.Parameters.ValueKind == System.Text.Json.JsonValueKind.Object
            && request.Parameters.TryGetProperty("requestId", out var requestId)
            && requestId.ValueKind == System.Text.Json.JsonValueKind.String
            && Guid.TryParse(requestId.GetString(), out targetRequestId)
            && targetRequestId != Guid.Empty;
    }

    private static bool BypassesConcurrencyLimit(string method) => method is
        CancelMethod
        or CancelPendingMethod
        or "companion.unpair"
        or "elevation.release";

    private static bool IsTrackedOperation(string method) => method is not
        "companion.hello"
        and not "companion.authorize"
        and not CancelMethod;

    private async ValueTask SendResponseAsync(
        CompanionRequest request,
        CompanionResponse response,
        CompanionFrameAuthenticationContext? authenticationContext,
        CancellationToken cancellationToken)
    {
        _events.Record(new SecurityEvent(
            _timeProvider.GetUtcNow(),
            "companion",
            request.Method,
            response.Success ? "success" : "failure",
            response.Error?.Code));
        await SendAsync(
            CompanionFrameType.ControlJson,
            ControlMessageSerializer.Serialize(response),
            authenticationContext,
            cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask SendAsync(
        CompanionFrameType type,
        ReadOnlyMemory<byte> payload,
        CompanionFrameAuthenticationContext? authenticationContext,
        CancellationToken cancellationToken)
    {
        var trace = Interlocked.Increment(ref _diagnosticFrames) <= 16;
        RecordTransportStage("send-lock-wait", trace);
        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            RecordTransportStage("send-lock-acquired", trace);
            var sequence = checked((ulong)Interlocked.Increment(ref _outboundSequence));
            var frame = new CompanionFrame(
                CompanionProtocol.CurrentVersion,
                type,
                CompanionFrameFlags.Final,
                sequence,
                payload);
            if (_frameAuthenticator is not null)
            {
                RecordTransportStage("protect-begin", trace);
                frame = await _frameAuthenticator.ProtectOutboundAsync(
                    frame,
                    authenticationContext,
                    cancellationToken).ConfigureAwait(false);
                RecordTransportStage("protect-complete", trace);
            }

            RecordTransportStage("channel-send-begin", trace);
            await _channel.SendAsync(frame, cancellationToken).ConfigureAwait(false);
            RecordTransportStage("channel-send-complete", trace);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    private void RecordTransportStage(string stage, bool enabled)
    {
        if (enabled) _events.Record(new SecurityEvent(_timeProvider.GetUtcNow(), "transport", stage, "progress"));
    }
}
