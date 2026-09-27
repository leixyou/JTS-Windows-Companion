using System.Text.Json;

namespace JTS.WindowsCompanion.Setup;

internal enum CompanionSetupOperation
{
    Install,
    Uninstall,
}

internal sealed record CompanionSetupRecoveryMetadata(
    int SchemaVersion,
    CompanionSetupOperation Operation,
    string RegistrationSnapshot,
    bool PreviousAgentWasRunning,
    bool LaunchAgentAfterCommit,
    bool PurgeStateAfterCommit)
{
    private const int CurrentSchemaVersion = 1;
    private const int MaximumRegistrationSnapshotCharacters = 256 * 1024;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = false,
        WriteIndented = false,
    };

    public static CompanionSetupRecoveryMetadata Create(
        CompanionSetupOperation operation,
        string registrationSnapshot,
        bool previousAgentWasRunning,
        bool launchAgentAfterCommit,
        bool purgeStateAfterCommit)
    {
        var metadata = new CompanionSetupRecoveryMetadata(
            CurrentSchemaVersion,
            operation,
            registrationSnapshot,
            previousAgentWasRunning,
            launchAgentAfterCommit,
            purgeStateAfterCommit);
        Validate(metadata);
        return metadata;
    }

    public string Serialize()
    {
        Validate(this);
        return JsonSerializer.Serialize(this, JsonOptions);
    }

    public static CompanionSetupRecoveryMetadata Deserialize(string serialized)
    {
        if (string.IsNullOrWhiteSpace(serialized))
        {
            throw new InvalidDataException("The setup transaction recovery metadata is empty.");
        }

        CompanionSetupRecoveryMetadata metadata;
        try
        {
            metadata = JsonSerializer.Deserialize<CompanionSetupRecoveryMetadata>(serialized, JsonOptions)
                ?? throw new InvalidDataException("The setup transaction recovery metadata is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The setup transaction recovery metadata is malformed.", exception);
        }
        Validate(metadata);
        return metadata;
    }

    private static void Validate(CompanionSetupRecoveryMetadata metadata)
    {
        if (metadata.SchemaVersion != CurrentSchemaVersion ||
            !Enum.IsDefined(metadata.Operation) ||
            metadata.RegistrationSnapshot is null ||
            metadata.RegistrationSnapshot.Length > MaximumRegistrationSnapshotCharacters)
        {
            throw new InvalidDataException("The setup transaction recovery metadata is invalid.");
        }
        if (metadata.Operation == CompanionSetupOperation.Uninstall && metadata.LaunchAgentAfterCommit)
        {
            throw new InvalidDataException("An uninstall transaction cannot launch the Agent after commit.");
        }
        if (metadata.Operation == CompanionSetupOperation.Install && metadata.PurgeStateAfterCommit)
        {
            throw new InvalidDataException("An install transaction cannot purge Companion state after commit.");
        }
    }
}
