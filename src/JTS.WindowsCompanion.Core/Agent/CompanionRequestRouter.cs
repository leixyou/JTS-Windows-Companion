using System.Collections.Concurrent;
using JTS.WindowsCompanion.Files;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.Agent;

public delegate ValueTask<object?> CompanionMethodHandler(CompanionRequest request, CancellationToken cancellationToken);

public sealed class CompanionRequestRouter
{
    private readonly Dictionary<string, CompanionMethodHandler> _handlers = new(StringComparer.Ordinal);
    private readonly ICompanionAuthorizationGate _authorization;
    private readonly ConcurrentDictionary<string, CompanionResponse> _idempotentResponses = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, Task<CompanionResponse>> _idempotentOperations = new(StringComparer.Ordinal);
    private readonly Queue<string> _idempotencyOrder = new();
    private readonly object _idempotencySync = new();

    public CompanionRequestRouter(ICompanionAuthorizationGate authorization)
    {
        _authorization = authorization ?? throw new ArgumentNullException(nameof(authorization));
    }

    internal ICompanionAuthorizationGate Authorization => _authorization;

    public void Register(string method, CompanionMethodHandler handler)
    {
        if (!IsValidMethod(method))
        {
            throw new ArgumentException("Companion method names must be 1 to 128 characters.", nameof(method));
        }

        ArgumentNullException.ThrowIfNull(handler);
        if (!_handlers.TryAdd(method, handler))
        {
            throw new InvalidOperationException($"Companion method '{method}' is already registered.");
        }
    }

    public async ValueTask<CompanionResponse> DispatchAsync(
        CompanionRequest request,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.ProtocolVersion != CompanionProtocol.CurrentVersion)
        {
            return CompanionResponse.Fail(request.RequestId, "PROTOCOL_VERSION_UNSUPPORTED", "The protocol version is not supported.");
        }

        if (request.RequestId == Guid.Empty || !IsValidMethod(request.Method))
        {
            return CompanionResponse.Fail(request.RequestId, "REQUEST_INVALID", "The request ID and method are required.");
        }

        if (request.DeadlineUnixMilliseconds is { } deadline
            && now.ToUnixTimeMilliseconds() > deadline)
        {
            return CompanionResponse.Fail(request.RequestId, "DEADLINE_EXCEEDED", "The request deadline has elapsed.", retryable: true);
        }

        var authorization = _authorization.Evaluate(request.Method);
        if (!authorization.Allowed)
        {
            return CompanionResponse.Fail(
                request.RequestId,
                "PAIRING_REQUIRED",
                "Client authorization is required for this Companion method.");
        }

        var idempotencyCacheKey = BuildIdempotencyCacheKey(request, authorization);
        if (idempotencyCacheKey is not null
            && _idempotentResponses.TryGetValue(idempotencyCacheKey, out var cached))
        {
            return cached with { RequestId = request.RequestId };
        }

        if (!_handlers.TryGetValue(request.Method, out var handler))
        {
            return CompanionResponse.Fail(request.RequestId, "METHOD_NOT_FOUND", "The requested method is not available.");
        }

        if (idempotencyCacheKey is not null)
        {
            return await DispatchIdempotentAsync(
                request,
                handler,
                idempotencyCacheKey,
                cancellationToken).ConfigureAwait(false);
        }

        return await InvokeAsync(request, handler, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<CompanionResponse> DispatchIdempotentAsync(
        CompanionRequest request,
        CompanionMethodHandler handler,
        string idempotencyKey,
        CancellationToken cancellationToken)
    {
        var completion = new TaskCompletionSource<CompanionResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        var operation = _idempotentOperations.GetOrAdd(idempotencyKey, completion.Task);
        if (!ReferenceEquals(operation, completion.Task))
        {
            var existing = await operation.WaitAsync(cancellationToken).ConfigureAwait(false);
            return existing with { RequestId = request.RequestId };
        }

        try
        {
            var response = await InvokeAsync(request, handler, cancellationToken).ConfigureAwait(false);
            Cache(idempotencyKey, response);
            completion.TrySetResult(response);
            return response;
        }
        catch (OperationCanceledException)
        {
            completion.TrySetCanceled(cancellationToken);
            throw;
        }
        catch (Exception exception)
        {
            completion.TrySetException(exception);
            throw;
        }
        finally
        {
            _idempotentOperations.TryRemove(
                new KeyValuePair<string, Task<CompanionResponse>>(idempotencyKey, completion.Task));
        }
    }

    private static async ValueTask<CompanionResponse> InvokeAsync(
        CompanionRequest request,
        CompanionMethodHandler handler,
        CancellationToken cancellationToken)
    {

        CompanionResponse response;
        try
        {
            var result = await handler(request, cancellationToken).ConfigureAwait(false);
            response = CompanionResponse.Ok(request.RequestId, result);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (CompanionProtocolException exception)
        {
            response = CompanionResponse.Fail(request.RequestId, exception.Code, exception.Message);
        }
        catch (FileSandboxException exception)
        {
            response = CompanionResponse.Fail(request.RequestId, exception.Code, exception.Message);
        }
        catch (FileNotFoundException)
        {
            response = CompanionResponse.Fail(request.RequestId, "NOT_FOUND", "The requested resource was not found.");
        }
        catch (UnauthorizedAccessException)
        {
            response = CompanionResponse.Fail(request.RequestId, "NOT_AUTHORIZED", "The requested operation is not authorized.");
        }
        catch (ArgumentException)
        {
            response = CompanionResponse.Fail(request.RequestId, "REQUEST_INVALID", "The request parameters are invalid.");
        }
        catch (Exception)
        {
            response = CompanionResponse.Fail(request.RequestId, "INTERNAL_ERROR", "The request failed.", retryable: true);
        }

        return response;
    }

    private void Cache(string key, CompanionResponse response)
    {
        // The cache key includes a 64-character peer fingerprint and the method
        // in addition to the caller's bounded idempotency key.
        if (key.Length > 512)
        {
            return;
        }

        lock (_idempotencySync)
        {
            if (!_idempotentResponses.TryAdd(key, response))
            {
                return;
            }

            _idempotencyOrder.Enqueue(key);
            while (_idempotencyOrder.Count > 256)
            {
                _idempotentResponses.TryRemove(_idempotencyOrder.Dequeue(), out _);
            }
        }
    }

    private static bool IsValidMethod(string? method) =>
        !string.IsNullOrWhiteSpace(method)
        && method.Length <= 128
        && method.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_');

    private static string? BuildIdempotencyCacheKey(
        CompanionRequest request,
        CompanionAuthorizationDecision authorization)
    {
        if (authorization.BootstrapMethod
            || authorization.AuthorizationScope is not { Length: > 0 } scope
            || string.IsNullOrEmpty(request.IdempotencyKey)
            || request.IdempotencyKey.Length > 128)
        {
            return null;
        }

        return string.Concat(scope, "\0", request.Method, "\0", request.IdempotencyKey);
    }
}
