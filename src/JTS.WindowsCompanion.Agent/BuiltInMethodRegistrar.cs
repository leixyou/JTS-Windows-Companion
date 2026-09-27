using System.Text.Json;
using JTS.WindowsCompanion.Automation;
using JTS.WindowsCompanion.Elevation;
using JTS.WindowsCompanion.Files;
using JTS.WindowsCompanion.Managed;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Security;
using JTS.WindowsCompanion.Shell;
using JTS.WindowsCompanion.Transfers;
using JTS.WindowsCompanion.Worker;

namespace JTS.WindowsCompanion.Agent;

internal static class BuiltInMethodRegistrar
{
    public static void Register(
        CompanionRequestRouter router,
        ICompanionIdentity identity,
        CompanionAuthorizationSession authorization,
        IUiAutomationService automation,
        SandboxedFileService? files,
        CurrentUserPowerShellExecutor? shell,
        VrcFactoryWorkerBridge? vrcWorker,
        BinaryTransferCoordinator transfers,
        IElevationBrokerClient elevationBroker,
        IManagedServiceClient managedService,
        CompanionSensitiveInteractionCoordinator sensitiveInteractions)
    {
        ArgumentNullException.ThrowIfNull(router);
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(sensitiveInteractions);
        router.Register("companion.hello", async (request, cancellationToken) =>
        {
            var parameters = Deserialize<HelloParameters>(request.Parameters);
            var challenge = DecodeBase64(parameters.ChallengeBase64, "PAIRING_CHALLENGE_INVALID");
            var proof = await PairingProofService.CreateAsync(
                identity,
                challenge,
                parameters.Sequence,
                DateTimeOffset.UtcNow,
                cancellationToken).ConfigureAwait(false);
            var clientAuthorization = await authorization.BeginHandshakeAsync(
                challenge,
                cancellationToken).ConfigureAwait(false);
            var capabilities = Capabilities(
                files is not null,
                shell is not null,
                vrcWorker is not null,
                managedService.IsConfigured);
            return new CompanionHello(
                CompanionProtocol.CurrentVersion,
                typeof(BuiltInMethodRegistrar).Assembly.GetName().Version?.ToString() ?? "2.0.0",
                proof.DeviceId,
                proof.FingerprintSha256,
                Environment.MachineName,
                Environment.UserName,
                managedService.IsConfigured
                    ? CompanionOperatingMode.ManagedServiceAvailable
                    : CompanionOperatingMode.CurrentUser,
                capabilities,
                proof,
                clientAuthorization);
        });

        router.Register("companion.authorize", async (request, cancellationToken) =>
            await authorization.AuthorizeAsync(
                Deserialize<ClientAuthorizationProof>(request.Parameters),
                cancellationToken).ConfigureAwait(false));

        router.Register("companion.state", (_, _) => ValueTask.FromResult<object?>(new CompanionState(
            Connected: true,
            Paired: authorization.IsAuthorized,
            PairingStored: authorization.HasPersistedPeer,
            managedService.IsConfigured
                ? CompanionOperatingMode.ManagedServiceAvailable
                : CompanionOperatingMode.CurrentUser,
            StateRevision: authorization.StateRevision,
            ActiveTasks: 0,
            ActiveElevationLeases: elevationBroker.ActiveLeaseCount,
            DateTimeOffset.UtcNow)));

        router.Register("companion.unpair", async (_, cancellationToken) =>
        {
            using var interaction = sensitiveInteractions.Enter(
                CompanionSensitiveInteractionKind.Pairing);
            await authorization.RevokeAsync(cancellationToken).ConfigureAwait(false);
            return new { revoked = true, stateRevision = authorization.StateRevision };
        });

        RegisterAutomation(router, automation, sensitiveInteractions);
        FileMethodRegistrar.Register(router, files, transfers, sensitiveInteractions);
        RegisterShell(router, shell, elevationBroker, sensitiveInteractions);
        BinaryTransferMethodRegistrar.Register(router, transfers);
        VrcFactoryWorkerMethodRegistrar.Register(router, vrcWorker, sensitiveInteractions);
        RegisterElevation(router, elevationBroker, sensitiveInteractions);
        RegisterManagedService(router, managedService, sensitiveInteractions);
    }

    private static void RegisterAutomation(
        CompanionRequestRouter router,
        IUiAutomationService automation,
        CompanionSensitiveInteractionCoordinator sensitiveInteractions)
    {
        router.Register("uia.snapshot", async (request, cancellationToken) =>
        {
            using var interaction = sensitiveInteractions.Enter(
                CompanionSensitiveInteractionKind.DesktopAutomation);
            var parameters = Deserialize<SnapshotParameters>(request.Parameters);
            return await automation.SnapshotAsync(parameters.MaximumDepth, parameters.MaximumNodes, cancellationToken).ConfigureAwait(false);
        });
        router.Register("uia.find", async (request, cancellationToken) =>
        {
            using var interaction = sensitiveInteractions.Enter(
                CompanionSensitiveInteractionKind.DesktopAutomation);
            var parameters = Deserialize<FindParameters>(request.Parameters);
            return await automation.FindAsync(parameters.Selector, parameters.MaximumResults, cancellationToken).ConfigureAwait(false);
        });
        router.Register("uia.invoke", async (request, cancellationToken) =>
        {
            using var interaction = sensitiveInteractions.Enter(
                CompanionSensitiveInteractionKind.DesktopAutomation);
            await automation.InvokeAsync(Deserialize<SelectorParameters>(request.Parameters).Selector, cancellationToken).ConfigureAwait(false);
            return new { completed = true };
        });
        router.Register("uia.setValue", async (request, cancellationToken) =>
        {
            using var interaction = sensitiveInteractions.Enter(
                CompanionSensitiveInteractionKind.DesktopAutomation);
            var parameters = Deserialize<SetValueParameters>(request.Parameters);
            await automation.SetValueAsync(parameters.Selector, parameters.Value, cancellationToken).ConfigureAwait(false);
            return new { completed = true };
        });
        router.Register("uia.select", async (request, cancellationToken) =>
        {
            using var interaction = sensitiveInteractions.Enter(
                CompanionSensitiveInteractionKind.DesktopAutomation);
            await automation.SelectAsync(Deserialize<SelectorParameters>(request.Parameters).Selector, cancellationToken).ConfigureAwait(false);
            return new { completed = true };
        });
        router.Register("uia.wait", async (request, cancellationToken) =>
        {
            using var interaction = sensitiveInteractions.Enter(
                CompanionSensitiveInteractionKind.DesktopAutomation);
            var parameters = Deserialize<WaitParameters>(request.Parameters);
            return await automation.WaitAsync(
                parameters.Selector,
                TimeSpan.FromMilliseconds(parameters.TimeoutMilliseconds),
                cancellationToken).ConfigureAwait(false);
        });
    }

    private static void RegisterShell(
        CompanionRequestRouter router,
        CurrentUserPowerShellExecutor? shell,
        IElevationBrokerClient elevationBroker,
        CompanionSensitiveInteractionCoordinator sensitiveInteractions)
    {
        router.Register("shell.exec", async (request, cancellationToken) =>
        {
            using var interaction = sensitiveInteractions.Enter(
                CompanionSensitiveInteractionKind.ShellMutation);
            var executor = RequireCompanionFeature(shell, "SHELL_NOT_CONFIGURED");
            var parameters = Deserialize<ShellExecutionRequest>(request.Parameters);
            if (parameters.RequiresElevation)
            {
                return await elevationBroker.ExecuteAsync(parameters, cancellationToken).ConfigureAwait(false);
            }

            return await executor.ExecuteAsync(parameters, cancellationToken).ConfigureAwait(false);
        });
    }

    private static void RegisterElevation(
        CompanionRequestRouter router,
        IElevationBrokerClient broker,
        CompanionSensitiveInteractionCoordinator sensitiveInteractions)
    {
        router.Register("elevation.request", async (request, cancellationToken) =>
        {
            using var interaction = sensitiveInteractions.Enter(
                CompanionSensitiveInteractionKind.ElevationPrompt);
            return await broker.RequestAsync(
                Deserialize<PowerShellElevationRequest>(request.Parameters),
                cancellationToken).ConfigureAwait(false);
        });
        router.Register("elevation.status", async (request, cancellationToken) =>
            await broker.GetStatusAsync(
                Deserialize<LeaseIdParameters>(request.Parameters).LeaseId,
                cancellationToken).ConfigureAwait(false));
        router.Register("elevation.release", async (request, cancellationToken) =>
        {
            await broker.ReleaseAsync(
                Deserialize<LeaseIdParameters>(request.Parameters).LeaseId,
                cancellationToken).ConfigureAwait(false);
            return new { released = true };
        });
    }

    private static void RegisterManagedService(
        CompanionRequestRouter router,
        IManagedServiceClient managedService,
        CompanionSensitiveInteractionCoordinator sensitiveInteractions)
    {
        router.Register("managed.execute", async (request, cancellationToken) =>
        {
            using var interaction = sensitiveInteractions.Enter(
                CompanionSensitiveInteractionKind.ManagedMutation);
            var parameters = Deserialize<ManagedOperationParameters>(request.Parameters);
            return await managedService.ExecuteAsync(
                new ManagedOperationRequest(
                    parameters.ProviderId,
                    parameters.OperationId,
                    parameters.Arguments,
                    new HashSet<string>(parameters.RequestedRootIds, StringComparer.Ordinal),
                    TimeSpan.FromMilliseconds(parameters.TimeoutMilliseconds)),
                cancellationToken).ConfigureAwait(false);
        });
    }

    private static IReadOnlyList<string> Capabilities(
        bool files,
        bool shell,
        bool worker,
        bool managedService)
    {
        var capabilities = new List<string>
        {
            "companion.hello",
            "companion.authorize",
            "companion.state",
            "companion.unpair",
            "companion.cancel",
            "companion.cancelPending",
            "uia.snapshot",
            "uia.find",
            "uia.invoke",
            "uia.setValue",
            "uia.select",
            "uia.wait",
            "elevation.request",
            "elevation.status",
            "elevation.release",
            "transfer.begin",
            "transfer.finalize",
            "transfer.download",
            "transfer.release",
        };
        if (files)
        {
            capabilities.AddRange([
                "files.list",
                "files.stat",
                "files.read",
                "files.write",
                "files.upload",
                "files.download",
            ]);
        }

        if (shell)
        {
            capabilities.Add("shell.exec");
        }

        if (worker)
        {
            capabilities.AddRange(["worker.doctor", "worker.submit", "worker.status", "worker.cancel", "worker.collect"]);
        }

        if (managedService)
        {
            capabilities.Add("managed.execute");
        }

        return capabilities;
    }

    private static T Deserialize<T>(JsonElement element) =>
        element.Deserialize<T>(ControlMessageSerializer.Options)
        ?? throw new CompanionProtocolException("REQUEST_INVALID", "The request parameters are missing.");

    private static byte[] DecodeBase64(string value, string errorCode)
    {
        try
        {
            return Convert.FromBase64String(value);
        }
        catch (FormatException)
        {
            throw new CompanionProtocolException(errorCode, "The request contains invalid base64 data.");
        }
    }

    private static T RequireCompanionFeature<T>(T? service, string errorCode)
        where T : class => service ?? throw new CompanionProtocolException(
            errorCode,
            "The requested companion feature is not configured.");

    private sealed record HelloParameters(string ChallengeBase64, ulong Sequence);

    private sealed record SnapshotParameters(int MaximumDepth = 8, int MaximumNodes = 2_000);

    private sealed record FindParameters(UiaSelector Selector, int MaximumResults = 100);

    private sealed record SelectorParameters(UiaSelector Selector);

    private sealed record SetValueParameters(UiaSelector Selector, string Value);

    private sealed record WaitParameters(UiaSelector Selector, int TimeoutMilliseconds = 30_000);

    private sealed record LeaseIdParameters(Guid LeaseId);

    private sealed record ManagedOperationParameters(
        string ProviderId,
        string OperationId,
        IReadOnlyDictionary<string, string> Arguments,
        IReadOnlyList<string> RequestedRootIds,
        int TimeoutMilliseconds);
}
