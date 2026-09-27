using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.Agent;

public enum CompanionOperatingMode
{
    CurrentUser,
    ManagedServiceAvailable,
}

public sealed record CompanionHello(
    int ProtocolVersion,
    string AgentVersion,
    Guid DeviceId,
    string DeviceFingerprintSha256,
    string MachineName,
    string UserName,
    CompanionOperatingMode Mode,
    IReadOnlyList<string> Capabilities,
    PairingProof PairingProof,
    CompanionAuthorizationChallenge ClientAuthorization);

public sealed record CompanionState(
    bool Connected,
    bool Paired,
    bool PairingStored,
    CompanionOperatingMode Mode,
    ulong StateRevision,
    int ActiveTasks,
    int ActiveElevationLeases,
    DateTimeOffset Timestamp);
