using System.Text.Json;
using JTS.WindowsCompanion.Relay;

namespace JTS.WindowsCompanion.Enrollment;

internal interface IRevocationRelay
{
    Task<IReadOnlyList<RevocationDelivery>> PollAsync(CancellationToken token);
    Task CompleteAsync(RevocationReceipt receipt, CancellationToken token);
}

internal sealed class RevocationRelayClient(RelayControlClient relay) : IRevocationRelay
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    public async Task<IReadOnlyList<RevocationDelivery>> PollAsync(CancellationToken token)
    {
        using var result = await relay.ExchangeRevocationsAsync(new { action = "poll" }, token).ConfigureAwait(false);
        EnrollmentCrypto.Fields(result.RootElement, "revocations");
        var items = result.RootElement.GetProperty("revocations");
        if (items.ValueKind != JsonValueKind.Array || items.GetArrayLength() > 32) throw RevocationRequest.Invalid();
        var output = new List<RevocationDelivery>();
        foreach (var item in items.EnumerateArray())
        {
            EnrollmentCrypto.Fields(item, "revocationId", "requestHash", "state", "revocation", "controllerSPKIBase64");
            var request = RevocationRequest.Parse(item.GetProperty("revocation"));
            if (item.GetProperty("revocationId").GetString() != request.RevocationId || item.GetProperty("state").GetString() != "pending"
                || item.GetProperty("requestHash").GetString() != request.RequestHash) throw RevocationRequest.Invalid();
            output.Add(new(request, item.GetProperty("controllerSPKIBase64").GetString() ?? throw RevocationRequest.Invalid()));
        }
        if (output.Select(i => i.Revocation.RevocationId).Distinct().Count() != output.Count) throw RevocationRequest.Invalid();
        return output;
    }
    public async Task CompleteAsync(RevocationReceipt receipt, CancellationToken token)
    {
        using var result = await relay.ExchangeRevocationsAsync(new { action = "complete", receipt = JsonSerializer.SerializeToElement(receipt, Json) }, token).ConfigureAwait(false);
        var p = result.RootElement;
        EnrollmentCrypto.Fields(p, "revocationId", "requestHash", "state", "revocation", "controllerSPKIBase64", "receipt");
        if (p.GetProperty("revocationId").GetString() != receipt.RevocationId || p.GetProperty("requestHash").GetString() != receipt.RequestHash
            || p.GetProperty("state").GetString() != "complete") throw RevocationRequest.Invalid();
        var exact = JsonSerializer.SerializeToElement(receipt, Json);
        EnrollmentCrypto.Fields(p.GetProperty("receipt"), "version", "revocationId", "requestHash", "controllerDeviceId", "peerDeviceId", "revokedAtUnixSeconds", "signatureBase64");
        foreach (var field in exact.EnumerateObject())
            if (field.Value.ToString() != p.GetProperty("receipt").GetProperty(field.Name).ToString()) throw RevocationRequest.Invalid();
    }
}
