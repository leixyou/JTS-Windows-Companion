using System.Text.Json;
using JTS.WindowsCompanion.Worker;

namespace JTS.WindowsCompanion.Tests;

public sealed class WorkerTests
{
    [Fact]
    public async Task Coordinator_RunsOnlyRegisteredFixedOperations()
    {
        var registry = new WorkerTaskRegistry();
        registry.Register(new TestProvider());
        await using var coordinator = new WorkerTaskCoordinator(registry);
        var request = CreateRequest("clean-install-auto");

        coordinator.Submit(request);
        var status = await WaitForCompletionAsync(coordinator, request.TaskId);
        var result = coordinator.Collect(request.TaskId);

        Assert.Equal(WorkerTaskState.Succeeded, status.State);
        Assert.True(result.Success);
        Assert.Equal("OK", result.ResultCode);
        Assert.Throws<KeyNotFoundException>(() => coordinator.Submit(CreateRequest("shell.exec")));
    }

    [Fact]
    public void Registry_RejectsArbitraryShellProvider()
    {
        var registry = new WorkerTaskRegistry();
        Assert.Throws<ArgumentException>(() => registry.Register(new ShellProvider()));
    }

    private static WorkerTaskRequest CreateRequest(string operation) => new(
        Guid.NewGuid(),
        "vrc-factory",
        operation,
        "avatar-pilot-001",
        new string('A', 64),
        JsonSerializer.SerializeToElement(new { package = "avatar-pilot-001.zip" }));

    private static async Task<WorkerTaskStatus> WaitForCompletionAsync(WorkerTaskCoordinator coordinator, Guid taskId)
    {
        for (var attempt = 0; attempt < 100; attempt++)
        {
            var status = coordinator.GetStatus(taskId);
            if (status.State is not WorkerTaskState.Queued and not WorkerTaskState.Running)
            {
                return status;
            }

            await Task.Delay(10);
        }

        throw new TimeoutException("The test worker did not complete.");
    }

    private sealed class TestProvider : IWorkerTaskProvider
    {
        public string ProviderId => "vrc-factory";

        public IReadOnlySet<string> SupportedOperations { get; } = new HashSet<string>(["clean-install-auto"]);

        public void Validate(WorkerTaskRequest request)
        {
            if (request.ArtifactId != "avatar-pilot-001")
            {
                throw new ArgumentException("Unexpected artifact.", nameof(request));
            }
        }

        public ValueTask<WorkerTaskResult> ExecuteAsync(WorkerTaskRequest request, CancellationToken cancellationToken) =>
            ValueTask.FromResult(new WorkerTaskResult(
                true,
                "OK",
                "results/avatar-pilot-001.zip",
                new string('B', 64),
                JsonSerializer.SerializeToElement(new { operation = request.Operation })));
    }

    private sealed class ShellProvider : IWorkerTaskProvider
    {
        public string ProviderId => "unsafe";

        public IReadOnlySet<string> SupportedOperations { get; } = new HashSet<string>(["shell.exec"]);

        public void Validate(WorkerTaskRequest request)
        {
        }

        public ValueTask<WorkerTaskResult> ExecuteAsync(WorkerTaskRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
