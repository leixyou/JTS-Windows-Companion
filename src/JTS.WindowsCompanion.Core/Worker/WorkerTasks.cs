using System.Collections.Concurrent;
using System.Text.Json;

namespace JTS.WindowsCompanion.Worker;

public enum WorkerTaskState
{
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

public sealed record WorkerTaskRequest(
    Guid TaskId,
    string ProviderId,
    string Operation,
    string ArtifactId,
    string InputSha256,
    JsonElement Parameters);

public sealed record WorkerTaskResult(
    bool Success,
    string ResultCode,
    string? ArtifactPath,
    string? ArtifactSha256,
    JsonElement Metadata);

public sealed record WorkerTaskStatus(
    Guid TaskId,
    WorkerTaskState State,
    DateTimeOffset SubmittedAt,
    DateTimeOffset? StartedAt,
    DateTimeOffset? CompletedAt,
    string? ResultCode);

public interface IWorkerTaskProvider
{
    string ProviderId { get; }

    IReadOnlySet<string> SupportedOperations { get; }

    void Validate(WorkerTaskRequest request);

    ValueTask<WorkerTaskResult> ExecuteAsync(WorkerTaskRequest request, CancellationToken cancellationToken);
}

public sealed class WorkerTaskRegistry
{
    private readonly Dictionary<string, IWorkerTaskProvider> _providers = new(StringComparer.Ordinal);

    public void Register(IWorkerTaskProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ValidateIdentifier(provider.ProviderId, nameof(provider));
        if (provider.SupportedOperations.Count == 0)
        {
            throw new ArgumentException("Worker task providers must expose at least one fixed operation.", nameof(provider));
        }

        foreach (var operation in provider.SupportedOperations)
        {
            ValidateIdentifier(operation, nameof(provider));
            if (IsShellOperation(operation))
            {
                throw new ArgumentException("Worker task providers cannot register an arbitrary shell operation.", nameof(provider));
            }
        }

        if (!_providers.TryAdd(provider.ProviderId, provider))
        {
            throw new InvalidOperationException($"Worker task provider '{provider.ProviderId}' is already registered.");
        }
    }

    public IWorkerTaskProvider Resolve(string providerId, string operation)
    {
        if (!_providers.TryGetValue(providerId, out var provider)
            || !provider.SupportedOperations.Contains(operation))
        {
            throw new KeyNotFoundException("The requested worker provider or operation is not registered.");
        }

        return provider;
    }

    public IReadOnlyList<(string ProviderId, IReadOnlySet<string> Operations)> List() => _providers.Values
        .Select(provider => (provider.ProviderId, provider.SupportedOperations))
        .OrderBy(provider => provider.ProviderId, StringComparer.Ordinal)
        .ToArray();

    private static void ValidateIdentifier(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length > 128
            || value.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_')))
        {
            throw new ArgumentException("Provider and operation IDs must be stable ASCII identifiers.", parameterName);
        }
    }

    private static bool IsShellOperation(string operation) =>
        operation.Equals("shell", StringComparison.OrdinalIgnoreCase)
        || operation.Equals("shell.exec", StringComparison.OrdinalIgnoreCase)
        || operation.Equals("powershell", StringComparison.OrdinalIgnoreCase)
        || operation.Equals("cmd", StringComparison.OrdinalIgnoreCase);
}

public sealed class WorkerTaskCoordinator : IAsyncDisposable
{
    private readonly WorkerTaskRegistry _registry;
    private readonly ConcurrentDictionary<Guid, TaskEntry> _tasks = new();

    public WorkerTaskCoordinator(WorkerTaskRegistry registry)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
    }

    public WorkerTaskStatus Submit(WorkerTaskRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.TaskId == Guid.Empty
            || string.IsNullOrWhiteSpace(request.ArtifactId)
            || !IsSha256(request.InputSha256))
        {
            throw new ArgumentException("Worker tasks require a task ID, artifact ID, and SHA-256 input digest.", nameof(request));
        }

        var provider = _registry.Resolve(request.ProviderId, request.Operation);
        provider.Validate(request);
        var entry = new TaskEntry(request, provider);
        if (!_tasks.TryAdd(request.TaskId, entry))
        {
            throw new InvalidOperationException("The worker task ID has already been submitted.");
        }

        entry.Execution = Task.Run(() => RunAsync(entry));
        return entry.GetStatus();
    }

    public WorkerTaskStatus GetStatus(Guid taskId) => GetEntry(taskId).GetStatus();

    public WorkerTaskResult Collect(Guid taskId)
    {
        var entry = GetEntry(taskId);
        lock (entry.Sync)
        {
            if (entry.State is WorkerTaskState.Queued or WorkerTaskState.Running)
            {
                throw new InvalidOperationException("The worker task is not complete.");
            }

            return entry.Result ?? throw new InvalidOperationException("The worker task ended without a result.");
        }
    }

    public void Cancel(Guid taskId) => GetEntry(taskId).Cancellation.Cancel();

    public async ValueTask DisposeAsync()
    {
        foreach (var entry in _tasks.Values)
        {
            entry.Cancellation.Cancel();
        }

        await Task.WhenAll(_tasks.Values.Select(entry => entry.Execution ?? Task.CompletedTask)).ConfigureAwait(false);
        foreach (var entry in _tasks.Values)
        {
            entry.Cancellation.Dispose();
        }
    }

    private async Task RunAsync(TaskEntry entry)
    {
        lock (entry.Sync)
        {
            entry.State = WorkerTaskState.Running;
            entry.StartedAt = DateTimeOffset.UtcNow;
        }

        try
        {
            var result = await entry.Provider.ExecuteAsync(entry.Request, entry.Cancellation.Token).ConfigureAwait(false);
            lock (entry.Sync)
            {
                entry.Result = result;
                entry.State = result.Success ? WorkerTaskState.Succeeded : WorkerTaskState.Failed;
            }
        }
        catch (OperationCanceledException) when (entry.Cancellation.IsCancellationRequested)
        {
            lock (entry.Sync)
            {
                entry.Result = new WorkerTaskResult(
                    false,
                    "CANCELLED",
                    null,
                    null,
                    JsonSerializer.SerializeToElement(new { }));
                entry.State = WorkerTaskState.Cancelled;
            }
        }
        catch (Exception)
        {
            lock (entry.Sync)
            {
                entry.Result = new WorkerTaskResult(
                    false,
                    "PROVIDER_FAILED",
                    null,
                    null,
                    JsonSerializer.SerializeToElement(new { }));
                entry.State = WorkerTaskState.Failed;
            }
        }
        finally
        {
            lock (entry.Sync)
            {
                entry.CompletedAt = DateTimeOffset.UtcNow;
            }
        }
    }

    private TaskEntry GetEntry(Guid taskId) => _tasks.TryGetValue(taskId, out var entry)
        ? entry
        : throw new KeyNotFoundException("The worker task was not found.");

    private static bool IsSha256(string value) =>
        value.Length == 64 && value.All(character => char.IsAsciiHexDigit(character));

    private sealed class TaskEntry
    {
        public TaskEntry(WorkerTaskRequest request, IWorkerTaskProvider provider)
        {
            Request = request;
            Provider = provider;
        }

        public object Sync { get; } = new();

        public WorkerTaskRequest Request { get; }

        public IWorkerTaskProvider Provider { get; }

        public CancellationTokenSource Cancellation { get; } = new();

        public Task? Execution { get; set; }

        public WorkerTaskState State { get; set; } = WorkerTaskState.Queued;

        public DateTimeOffset SubmittedAt { get; } = DateTimeOffset.UtcNow;

        public DateTimeOffset? StartedAt { get; set; }

        public DateTimeOffset? CompletedAt { get; set; }

        public WorkerTaskResult? Result { get; set; }

        public WorkerTaskStatus GetStatus()
        {
            lock (Sync)
            {
                return new WorkerTaskStatus(
                    Request.TaskId,
                    State,
                    SubmittedAt,
                    StartedAt,
                    CompletedAt,
                    Result?.ResultCode);
            }
        }
    }
}
