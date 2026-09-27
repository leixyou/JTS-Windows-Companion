using System.Security.Cryptography;
using JTS.WindowsCompanion.Relay;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.Enrollment;

/// <summary>Polls without holding local management locks; the apply callback serializes durable revoke with enrollment.</summary>
internal sealed class RevocationProcessor : IDisposable
{
    private readonly RevocationJournal _journal;
    private readonly IRevocationRelay _relay;
    private readonly RelayEndpointIdentity _identity;
    private readonly string _origin;
    private readonly TimeProvider _clock;
    private readonly Func<RevocationRequest, CancellationToken, Task> _apply;
    internal RevocationProcessor(string path, string origin, RelayEndpointIdentity identity, ITaskPayloadProtector protector,
        Action<string> checkPath, IRevocationRelay relay, TimeProvider clock, Func<RevocationRequest, CancellationToken, Task> apply)
    { _journal = new(path, identity.DeviceId, protector, checkPath); _origin = origin; _identity = identity; _relay = relay; _clock = clock; _apply = apply; }
    internal async Task StepAsync(CancellationToken token)
    {
        // Durable pending work is completed even if the relay is offline or suppresses a subsequent poll.
        var pending = _journal.Entries.FirstOrDefault(e => !e.Delivered && !e.Rejected);
        if (pending is not null) { await TryCompleteAsync(pending, token).ConfigureAwait(false); return; }
        IReadOnlyList<RevocationDelivery> messages;
        try { messages = await _relay.PollAsync(token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch (Exception e) when (IsRetryable(e)) { return; }
        foreach (var delivery in messages)
        {
            try
            {
                delivery.Revocation.Verify(_origin, _identity.DeviceId, delivery.ControllerSPKIBase64);
                var existing = _journal.Entries.SingleOrDefault(e => e.Delivery.Revocation.RevocationId == delivery.Revocation.RevocationId);
                if (existing is not null && existing.Delivery != delivery) throw RevocationRequest.Invalid();
                var entry = existing ?? new RevocationEntry(delivery);
                if (existing is null) _journal.Save(entry);
                if (existing?.Rejected == true) continue;
                // Bound each tick to one remote completion. Status/revoke cannot be blocked by a fleet-sized retry backlog.
                await TryCompleteAsync(entry, token).ConfigureAwait(false);
                return;
            }
            catch (EnrollmentException) { /* An untrusted mailbox never authorizes malformed or foreign requests. */ }
            catch (CryptographicException) { }
        }
    }
    private async Task TryCompleteAsync(RevocationEntry entry, CancellationToken token)
    {
        try
        {
            var request = entry.Delivery.Revocation;
            request.Verify(_origin, _identity.DeviceId, entry.Delivery.ControllerSPKIBase64);
            if (entry.Receipt is null)
            {
                try { await _apply(request, token).ConfigureAwait(false); } // Durable tombstones AND live executor drain precede success.
                catch (EnrollmentException)
                { _journal.Save(entry with { Rejected = true }); return; } // Signed but foreign epoch/capability: never acknowledge or let it starve valid requests.
                var receipt = new RevocationReceipt(2, request.RevocationId, request.RequestHash, request.ControllerDeviceId,
                    request.PeerDeviceId, _clock.GetUtcNow().ToUnixTimeSeconds(), "");
                receipt = receipt with { SignatureBase64 = Convert.ToBase64String(_identity.SignRevocationReceipt(receipt.Transcript())) };
                entry = entry with { Receipt = receipt }; _journal.Save(entry);
            }
            await _relay.CompleteAsync(entry.Receipt!, token).ConfigureAwait(false);
            if (!entry.Delivered) _journal.Save(entry with { Delivered = true });
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch (Exception e) when (IsRetryable(e)) { /* Pending is not success. Retry the same signed receipt after a lost acknowledgement. */ }
    }
    private static bool IsRetryable(Exception e) => e is HttpRequestException or OperationCanceledException or TimeoutException or RelayProtocolException or EnrollmentException or CryptographicException or System.Text.Json.JsonException or InvalidOperationException or KeyNotFoundException or FormatException;
    public void Dispose() => _journal.Dispose();
}
