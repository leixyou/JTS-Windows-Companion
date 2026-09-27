using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using JTS.WindowsCompanion.WorkerService;

namespace JTS.WindowsCompanion.UnattendedInstallation;

/// <summary>Owns only registrations created by this live first-install transaction. Dispose never uninstalls.</summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsInstalledServices : IDisposable
{
    private readonly SemaphoreSlim _operations = new(1, 1);
    private readonly List<OwnedService> _created = [];
    private bool _registrationAttempted, _registered, _activationAttempted, _disposed;
    internal bool ActivationAttempted => Volatile.Read(ref _activationAttempted);

    internal void RegisterDisabled(LocalAccountIdentity authority, AccountPassword authorityPassword,
        LocalAccountIdentity worker, AccountPassword workerPassword, string programDirectory, Guid enrollmentId)
    {
        _operations.Wait();
        try
        {
            ThrowIfDisposed();
            if (_registrationAttempted) throw new UnattendedInstallationException("INSTALL_SERVICE_REGISTRATION_ALREADY_ATTEMPTED");
            _registrationAttempted = true;
            if (!OperatingSystem.IsWindowsVersionAtLeast(10) || !Environment.Is64BitProcess)
                throw new PlatformNotSupportedException("Windows x64 service installation is required.");
            var definitions = InstalledServiceDefinition.Create(authority, worker, programDirectory, enrollmentId);
            using var authorityProgram = WindowsServiceProgramTrust.Open(definitions.Authority.Executable, CompanionServiceProgram.Authority);
            using var workerProgram = WindowsServiceProgramTrust.Open(definitions.Worker.Executable, CompanionServiceProgram.Worker);
            using var manager = InstallationScmNative.OpenManager(null, null, 3); // CONNECT | CREATE_SERVICE.
            InstallationScmNative.Require(!manager.IsInvalid);
            RequireAbsent(manager, definitions.Authority.Name); RequireAbsent(manager, definitions.Worker.Name);
            Create(manager, definitions.Worker, workerPassword);
            Create(manager, definitions.Authority, authorityPassword);
            foreach (var service in _created)
            {
                InstalledServiceInspection.Validate(service.Handle, service.Definition, 4);
                InstalledServiceInspection.RequireStoppedDisabled(service.Handle);
            }
            _registered = true;
        }
        finally { _operations.Release(); }
    }

    internal async Task ActivateAsync(CancellationToken cancellationToken)
    {
        await _operations.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (!_registered || _activationAttempted) throw new UnattendedInstallationException("INSTALL_SERVICE_ACTIVATION_STATE_REJECTED");
            cancellationToken.ThrowIfCancellationRequested();
            // The caller must durably record activation intent and commit protected state before this call.
            // From here even a failed RPC or cancellation forbids automatic rollback/deletion.
            Volatile.Write(ref _activationAttempted, true);
            foreach (var service in _created)
            {
                InstalledServiceInspection.Validate(service.Handle, service.Definition, 4);
                InstalledServiceInspection.RequireStoppedDisabled(service.Handle);
            }
            var worker = _created.Single(s => s.Definition.Name == InstalledServiceDefinition.WorkerName);
            var authority = _created.Single(s => s.Definition.Name == InstalledServiceDefinition.AuthorityName);
            InstalledServiceSettings.SetStartType(worker.Handle, worker.Definition.ActiveStartType);
            InstalledServiceSettings.SetStartType(authority.Handle, authority.Definition.ActiveStartType);
            InstalledServiceInspection.Validate(worker.Handle, worker.Definition, 3);
            InstalledServiceInspection.Validate(authority.Handle, authority.Definition, 2);
            cancellationToken.ThrowIfCancellationRequested();
            // StartService is a synchronous SCM RPC. Observe its actual completion; cancellation must
            // not discard a still-live start operation or imply that a service was never started.
            var started = await Task.Run(() => InstallationScmNative.StartService(authority.Handle, 0, IntPtr.Zero)).ConfigureAwait(false);
            if (!started) throw new UnattendedInstallationException("INSTALL_AUTHORITY_START_FAILED_PRESERVE_STATE");
            var timer = Stopwatch.StartNew();
            while (timer.Elapsed < TimeSpan.FromSeconds(35))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var state = InstalledServiceInspection.State(authority.Handle);
                if (state.State == 4 && state.Pid != 0) return; // Local SCM Running, not remote pairing/online acceptance.
                if (state.State != 2) throw new UnattendedInstallationException("INSTALL_AUTHORITY_STOPPED_PRESERVE_STATE");
                await Task.Delay(100, cancellationToken).ConfigureAwait(false);
            }
            throw new UnattendedInstallationException("INSTALL_AUTHORITY_START_TIMEOUT_PRESERVE_STATE");
        }
        finally { _operations.Release(); }
    }

    internal void RollbackNeverActivated()
    {
        _operations.Wait();
        try
        {
            ThrowIfDisposed();
            if (_activationAttempted) throw new UnattendedInstallationException("INSTALL_SERVICE_ACTIVATION_REQUIRES_EXPLICIT_RECOVERY");
            // Check all owned objects before marking any. Never open by name to perform deletion.
            foreach (var service in _created) InstalledServiceInspection.RequireStoppedDisabled(service.Handle);
            var failed = false;
            for (var i = _created.Count - 1; i >= 0; i--)
            {
                var service = _created[i];
                if (!InstallationScmNative.DeleteService(service.Handle)) { failed = true; continue; }
                service.Handle.Dispose(); _created.RemoveAt(i);
            }
            _registered = false;
            if (failed) throw new UnattendedInstallationException("INSTALL_SERVICE_ROLLBACK_INCOMPLETE");
            // DeleteService marks deletion; another diagnostic handle may defer physical SCM removal.
            // All targets were disabled/stopped and only original CreateService handles were used.
        }
        finally { _operations.Release(); }
    }

    private void Create(InstallationServiceHandle manager, InstalledServiceDefinition definition, AccountPassword password)
    {
        var handle = InstallationScmNative.CreateService(manager, definition.Name, definition.DisplayName,
            InstallationScmNative.AllAccess, 0x10, 4, 1, definition.Command, null, IntPtr.Zero, null,
            definition.AccountName, password.Pointer);
        if (handle.IsInvalid) { handle.Dispose(); throw new UnattendedInstallationException("INSTALL_SERVICE_CREATE_ONLY_FAILED"); }
        _created.Add(new(handle, definition)); // Capture ownership before any subsequent configuration can fail.
        GC.KeepAlive(password);
        InstalledServiceSettings.Configure(handle, definition);
    }
    private static void RequireAbsent(InstallationServiceHandle manager, string name)
    {
        using var existing = InstallationScmNative.OpenService(manager, name, 1);
        var error = Marshal.GetLastWin32Error();
        if (!existing.IsInvalid || error != 1060) throw new UnattendedInstallationException("INSTALL_SERVICE_NAME_NOT_AVAILABLE");
    }
    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
    public void Dispose()
    {
        _operations.Wait();
        try
        {
            if (_disposed) return;
            _disposed = true;
            foreach (var service in _created) service.Handle.Dispose();
            _created.Clear();
        }
        finally { _operations.Release(); }
    }
    private sealed record OwnedService(InstallationServiceHandle Handle, InstalledServiceDefinition Definition);
}
