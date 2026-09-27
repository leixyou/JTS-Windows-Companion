using JTS.WindowsCompanion.Agent;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.Worker;

public static class VrcFactoryWorkerMethodRegistrar
{
    public static void Register(
        CompanionRequestRouter router,
        VrcFactoryWorkerBridge? bridge,
        CompanionSensitiveInteractionCoordinator? sensitiveInteractions = null)
    {
        ArgumentNullException.ThrowIfNull(router);
        var interactions = sensitiveInteractions ?? new CompanionSensitiveInteractionCoordinator();
        Register(router, bridge, interactions, "worker.doctor", VrcFactoryWorkerAction.Doctor, mutation: false);
        Register(router, bridge, interactions, "worker.submit", VrcFactoryWorkerAction.Submit, mutation: true);
        Register(router, bridge, interactions, "worker.status", VrcFactoryWorkerAction.Status, mutation: false);
        Register(router, bridge, interactions, "worker.cancel", VrcFactoryWorkerAction.Cancel, mutation: true);
        Register(router, bridge, interactions, "worker.collect", VrcFactoryWorkerAction.Collect, mutation: true);
    }

    private static void Register(
        CompanionRequestRouter router,
        VrcFactoryWorkerBridge? bridge,
        CompanionSensitiveInteractionCoordinator sensitiveInteractions,
        string method,
        VrcFactoryWorkerAction action,
        bool mutation)
    {
        router.Register(method, async (request, cancellationToken) =>
        {
            if (bridge is null)
            {
                throw new CompanionProtocolException(
                    "WORKER_NOT_CONFIGURED",
                    "The requested companion feature is not configured.");
            }

            if (!mutation)
            {
                return await bridge.ExecuteAsync(action, request.Parameters, cancellationToken).ConfigureAwait(false);
            }

            using var interaction = sensitiveInteractions.Enter(
                CompanionSensitiveInteractionKind.WorkerMutation);
            return await bridge.ExecuteAsync(action, request.Parameters, cancellationToken).ConfigureAwait(false);
        });
    }
}
