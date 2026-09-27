using JTS.WindowsCompanion.Setup;

namespace JTS.WindowsCompanion.Tests;

public sealed class CompanionSetupRecoveryMetadataTests
{
    [Fact]
    public void RoundTrip_PreservesTheAgentLifecycleIntent()
    {
        var metadata = CompanionSetupRecoveryMetadata.Create(
            CompanionSetupOperation.Install,
            "registration-snapshot",
            previousAgentWasRunning: true,
            launchAgentAfterCommit: false,
            purgeStateAfterCommit: false);

        var restored = CompanionSetupRecoveryMetadata.Deserialize(metadata.Serialize());

        Assert.Equal(CompanionSetupOperation.Install, restored.Operation);
        Assert.Equal("registration-snapshot", restored.RegistrationSnapshot);
        Assert.True(restored.PreviousAgentWasRunning);
        Assert.False(restored.LaunchAgentAfterCommit);
        Assert.False(restored.PurgeStateAfterCommit);
    }

    [Fact]
    public void Create_RejectsLaunchingTheAgentAfterUninstallCommit()
    {
        Assert.Throws<InvalidDataException>(() =>
            CompanionSetupRecoveryMetadata.Create(
                CompanionSetupOperation.Uninstall,
                "registration-snapshot",
                previousAgentWasRunning: true,
                launchAgentAfterCommit: true,
                purgeStateAfterCommit: false));
    }

    [Fact]
    public void RoundTrip_PreservesDurablePurgeIntentForUninstall()
    {
        var metadata = CompanionSetupRecoveryMetadata.Create(
            CompanionSetupOperation.Uninstall,
            "registration-snapshot",
            previousAgentWasRunning: true,
            launchAgentAfterCommit: false,
            purgeStateAfterCommit: true);

        var restored = CompanionSetupRecoveryMetadata.Deserialize(metadata.Serialize());

        Assert.Equal(CompanionSetupOperation.Uninstall, restored.Operation);
        Assert.True(restored.PurgeStateAfterCommit);
        Assert.False(restored.LaunchAgentAfterCommit);
    }

    [Fact]
    public void Create_RejectsPurgingStateAfterInstallCommit()
    {
        Assert.Throws<InvalidDataException>(() =>
            CompanionSetupRecoveryMetadata.Create(
                CompanionSetupOperation.Install,
                "registration-snapshot",
                previousAgentWasRunning: false,
                launchAgentAfterCommit: false,
                purgeStateAfterCommit: true));
    }

    [Fact]
    public void Deserialize_RejectsAnUnsupportedSchema()
    {
        const string serialized =
            "{\"SchemaVersion\":2,\"Operation\":0,\"RegistrationSnapshot\":\"snapshot\"," +
            "\"PreviousAgentWasRunning\":true,\"LaunchAgentAfterCommit\":true," +
            "\"PurgeStateAfterCommit\":false}";

        Assert.Throws<InvalidDataException>(() =>
            CompanionSetupRecoveryMetadata.Deserialize(serialized));
    }
}
