using JTS.WindowsCompanion.Files;
using JTS.WindowsCompanion.Lifecycle;

namespace JTS.WindowsCompanion.Agent;

internal sealed record VrcWorkerInstallation(string ExecutablePath, string ExecutableSha256);

internal sealed record AgentOptions(
    IReadOnlyList<FileRoot> FileRoots,
    VrcWorkerInstallation? VrcWorker,
    string? UacBrokerExecutablePath,
    string? ManagedServicePipeName,
    string? StartupReadyPipeName)
{
    public static AgentOptions Parse(string[] arguments)
    {
        var roots = new List<FileRoot>();
        string? vrcWorkerPath = null;
        string? vrcWorkerSha256 = null;
        string? uacBrokerPath = null;
        string? managedServicePipe = null;
        string? startupReadyPipe = null;
        for (var index = 0; index < arguments.Length; index++)
        {
            var argument = arguments[index];
            if (argument is "--vrc-worker" or
                "--vrc-worker-sha256" or
                "--uac-broker" or
                "--managed-service-pipe" or
                CompanionAgentReadinessContract.ArgumentName)
            {
                if (++index >= arguments.Length)
                {
                    throw new ArgumentException($"{argument} requires a value.");
                }

                if (argument == "--vrc-worker")
                {
                    if (vrcWorkerPath is not null)
                    {
                        throw new ArgumentException("--vrc-worker can be provided only once.");
                    }

                    vrcWorkerPath = arguments[index];
                }
                else if (argument == "--vrc-worker-sha256")
                {
                    if (vrcWorkerSha256 is not null)
                    {
                        throw new ArgumentException("--vrc-worker-sha256 can be provided only once.");
                    }

                    vrcWorkerSha256 = arguments[index];
                }
                else if (argument == "--uac-broker")
                {
                    if (uacBrokerPath is not null)
                    {
                        throw new ArgumentException("--uac-broker can be provided only once.");
                    }

                    uacBrokerPath = arguments[index];
                }
                else if (argument == "--managed-service-pipe")
                {
                    if (managedServicePipe is not null)
                    {
                        throw new ArgumentException("--managed-service-pipe can be provided only once.");
                    }

                    managedServicePipe = arguments[index];
                }
                else
                {
                    if (startupReadyPipe is not null)
                    {
                        throw new ArgumentException(
                            $"{CompanionAgentReadinessContract.ArgumentName} can be provided only once.");
                    }

                    CompanionAgentReadinessContract.ValidatePipeName(arguments[index]);
                    startupReadyPipe = arguments[index];
                }

                continue;
            }

            if (argument is not "--root" and not "--read-only-root")
            {
                throw new ArgumentException($"Unknown argument '{argument}'.");
            }

            if (++index >= arguments.Length)
            {
                throw new ArgumentException($"{argument} requires an id=path value.");
            }

            var specification = arguments[index];
            var separator = specification.IndexOf('=');
            if (separator <= 0 || separator == specification.Length - 1)
            {
                throw new ArgumentException($"{argument} requires an id=path value.");
            }

            roots.Add(new FileRoot(
                specification[..separator],
                specification[(separator + 1)..],
                ReadOnly: argument == "--read-only-root"));
        }

        if ((vrcWorkerPath is null) != (vrcWorkerSha256 is null))
        {
            throw new ArgumentException("--vrc-worker and --vrc-worker-sha256 must be configured together.");
        }

        var worker = vrcWorkerPath is null
            ? null
            : new VrcWorkerInstallation(vrcWorkerPath, vrcWorkerSha256!);
        if (uacBrokerPath is not null && roots.Count == 0)
        {
            throw new ArgumentException("--uac-broker requires at least one explicit file root.");
        }

        return new AgentOptions(
            roots,
            worker,
            uacBrokerPath,
            managedServicePipe,
            startupReadyPipe);
    }
}
