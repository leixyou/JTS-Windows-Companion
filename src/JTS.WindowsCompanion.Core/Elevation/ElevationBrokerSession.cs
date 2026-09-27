using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Protocol;

namespace JTS.WindowsCompanion.Elevation;

public sealed class ElevationBrokerSession
{
    public const int ProtocolVersion = 1;
    private readonly ElevationLeaseManager _leases;
    private readonly ElevatedPowerShellExecutor _executor;

    public ElevationBrokerSession(
        ElevationLeaseManager leases,
        ElevatedPowerShellExecutor executor)
    {
        _leases = leases ?? throw new ArgumentNullException(nameof(leases));
        _executor = executor ?? throw new ArgumentNullException(nameof(executor));
    }

    public async Task RunAsync(
        Stream stream,
        string nonce,
        int processId,
        CancellationToken cancellationToken)
    {
        ValidateNonce(nonce);
        var hello = Message(
            Guid.NewGuid(),
            ElevationBrokerMessageKind.Hello,
            nonce,
            new { processId, elevated = true });
        await LocalIpcJsonCodec.WriteAsync(stream, hello, cancellationToken).ConfigureAwait(false);

        var open = await LocalIpcJsonCodec.ReadAsync<ElevationBrokerMessage>(stream, cancellationToken).ConfigureAwait(false);
        ValidateMessage(open, ElevationBrokerMessageKind.OpenLease, nonce);
        var request = Deserialize<ElevationBrokerOpenLease>(open.Payload);
        ElevatedPowerShellExecutor.Validate(request.Action);
        var duration = TimeSpan.FromMilliseconds(request.DurationMilliseconds);
        var lease = _leases.IssueApproved(
            new ElevationLeaseRequest(
                open.MessageId,
                duration,
                [new ElevatedActionGrant(
                    request.Action.ActionId,
                    ElevatedActionKind.ApprovedPowerShell,
                    request.Action.PayloadSha256,
                    $"Approved PowerShell in {request.Action.WorkingDirectory}")]),
            userConfirmedOnSecureDesktop: true);
        await LocalIpcJsonCodec.WriteAsync(
            stream,
            Message(open.MessageId, ElevationBrokerMessageKind.LeaseOpened, nonce, lease),
            cancellationToken).ConfigureAwait(false);

        while (!cancellationToken.IsCancellationRequested)
        {
            ElevationBrokerMessage inbound;
            try
            {
                inbound = await LocalIpcJsonCodec.ReadAsync<ElevationBrokerMessage>(stream, cancellationToken).ConfigureAwait(false);
            }
            catch (EndOfStreamException)
            {
                return;
            }

            if (!string.Equals(inbound.Nonce, nonce, StringComparison.Ordinal))
            {
                throw new InvalidDataException("The elevation broker nonce does not match.");
            }

            try
            {
                var shouldExit = await DispatchAsync(stream, inbound, nonce, cancellationToken).ConfigureAwait(false);
                if (shouldExit)
                {
                    return;
                }
            }
            catch (UnauthorizedAccessException)
            {
                await WriteErrorAsync(stream, inbound, nonce, "NOT_AUTHORIZED", "The elevated action is not authorized.", cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (KeyNotFoundException)
            {
                await WriteErrorAsync(stream, inbound, nonce, "LEASE_NOT_FOUND", "The elevation lease is missing or expired.", cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (ArgumentException)
            {
                await WriteErrorAsync(stream, inbound, nonce, "REQUEST_INVALID", "The elevation broker request is invalid.", cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException)
            {
                await WriteErrorAsync(
                        stream,
                        inbound,
                        nonce,
                        "LEASE_EXPIRED",
                        "The elevation lease expired or was revoked during execution.",
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception)
            {
                await WriteErrorAsync(stream, inbound, nonce, "EXECUTION_FAILED", "The elevated action failed.", cancellationToken)
                    .ConfigureAwait(false);
            }
        }
    }

    private async ValueTask<bool> DispatchAsync(
        Stream stream,
        ElevationBrokerMessage message,
        string nonce,
        CancellationToken cancellationToken)
    {
        switch (message.Kind)
        {
            case ElevationBrokerMessageKind.Execute:
                {
                    var execute = Deserialize<ElevationBrokerExecute>(message.Payload);
                    var leaseCancellation = _leases.Authorize(
                        execute.LeaseId,
                        execute.ActionId,
                        ElevatedActionKind.ApprovedPowerShell,
                        execute.Action.CanonicalPayload);
                    using var executionCancellation = CancellationTokenSource.CreateLinkedTokenSource(
                        cancellationToken,
                        leaseCancellation);
                    var result = await _executor.ExecuteAsync(execute.Action, executionCancellation.Token).ConfigureAwait(false);
                    await LocalIpcJsonCodec.WriteAsync(
                        stream,
                        Message(message.MessageId, ElevationBrokerMessageKind.ExecutionResult, nonce, result),
                        cancellationToken).ConfigureAwait(false);
                    return false;
                }
            case ElevationBrokerMessageKind.Status:
                {
                    var lease = _leases.GetStatus(Deserialize<ElevationBrokerLeaseId>(message.Payload).LeaseId);
                    await LocalIpcJsonCodec.WriteAsync(
                        stream,
                        Message(message.MessageId, ElevationBrokerMessageKind.LeaseStatus, nonce, lease),
                        cancellationToken).ConfigureAwait(false);
                    return false;
                }
            case ElevationBrokerMessageKind.Release:
                {
                    var leaseId = Deserialize<ElevationBrokerLeaseId>(message.Payload).LeaseId;
                    _leases.Revoke(leaseId);
                    await LocalIpcJsonCodec.WriteAsync(
                        stream,
                        Message(message.MessageId, ElevationBrokerMessageKind.Released, nonce, new { released = true }),
                        cancellationToken).ConfigureAwait(false);
                    return true;
                }
            default:
                throw new ArgumentException("The elevation broker message kind is not accepted.", nameof(message));
        }
    }

    private static ElevationBrokerMessage Message<T>(
        Guid messageId,
        ElevationBrokerMessageKind kind,
        string nonce,
        T payload) => new(
            ProtocolVersion,
            messageId,
            kind,
            nonce,
            ControlMessageSerializer.ToElement(payload));

    private static async ValueTask WriteErrorAsync(
        Stream stream,
        ElevationBrokerMessage inbound,
        string nonce,
        string code,
        string message,
        CancellationToken cancellationToken) =>
        await LocalIpcJsonCodec.WriteAsync(
            stream,
            Message(inbound.MessageId, ElevationBrokerMessageKind.Error, nonce, new ElevationBrokerError(code, message)),
            cancellationToken).ConfigureAwait(false);

    private static T Deserialize<T>(JsonElement element) =>
        element.Deserialize<T>(ControlMessageSerializer.Options)
        ?? throw new ArgumentException("The elevation broker payload is missing.", nameof(element));

    private static void ValidateMessage(
        ElevationBrokerMessage message,
        ElevationBrokerMessageKind kind,
        string nonce)
    {
        if (message.Version != ProtocolVersion
            || message.MessageId == Guid.Empty
            || message.Kind != kind
            || !string.Equals(message.Nonce, nonce, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The elevation broker handshake is invalid.");
        }
    }

    private static void ValidateNonce(string nonce)
    {
        if (nonce.Length != 64 || !nonce.All(char.IsAsciiHexDigit))
        {
            throw new ArgumentException("The elevation broker nonce must be a 256-bit hexadecimal value.", nameof(nonce));
        }
    }
}
