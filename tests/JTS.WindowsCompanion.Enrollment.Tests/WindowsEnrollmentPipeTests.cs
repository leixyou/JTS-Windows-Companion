using System.IO.Pipes;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using Xunit;

namespace JTS.WindowsCompanion.Enrollment.Tests;

[SupportedOSPlatform("windows")]
public sealed class WindowsEnrollmentPipeTests
{
    [WindowsEnrollmentFact]
    public async Task AdministrativePipeChecksTheConnectedTokenNotMessageClaims()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        using var identity = WindowsIdentity.GetCurrent();
        using var server = WindowsEnrollmentNative.CreateServer(identity.User!.Value);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var accept = server.WaitForConnectionAsync(timeout.Token);
        using var handle = OpenPipe(@"\\.\pipe\" + EnrollmentManagementWire.PipeName, WindowsEnrollmentNative.ClientAccess, 0, IntPtr.Zero,
            3, 0x40000000 | 0x00110000, IntPtr.Zero);
        Assert.False(handle.IsInvalid);
        using var client = new NamedPipeClientStream(PipeDirection.InOut, true, true, handle);
        await accept;
        await client.WriteAsync(new byte[] { 1 }, timeout.Token);
        var message = new byte[1]; await server.ReadExactlyAsync(message, timeout.Token);
        var error = Record.Exception(() => WindowsEnrollmentNative.VerifyClient(server));
        var administrator = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        if (administrator && !identity.IsSystem && System.Diagnostics.Process.GetCurrentProcess().SessionId > 0) Assert.Null(error);
        else Assert.IsType<EnrollmentException>(error);
    }
    [WindowsEnrollmentFact]
    public async Task ClientRejectsAnImpostorPipeBeforeSendingAnEnrollmentSecret()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        using var identity = WindowsIdentity.GetCurrent();
        using var server = WindowsEnrollmentNative.CreateServer(identity.User!.Value);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var accept = server.WaitForConnectionAsync(timeout.Token);
        await Assert.ThrowsAsync<EnrollmentException>(() => WindowsEnrollmentManagementClient.EnrollAsync(EnrollmentCryptoTests.ValidCode, timeout.Token));
        // A standard user may be denied by the pipe ACL even before connecting. Admin CI exercises server attestation.
        if (new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            await accept;
            Assert.Equal(0, await server.ReadAsync(new byte[1], timeout.Token));
        }
        else { timeout.Cancel(); try { await accept; } catch (OperationCanceledException) { } }
    }
    [SupportedOSPlatform("windows")]
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafePipeHandle OpenPipe(string name, uint access, uint share, IntPtr attributes, uint disposition, uint flags, IntPtr template);
}

internal sealed class WindowsEnrollmentFactAttribute : FactAttribute
{
    public WindowsEnrollmentFactAttribute()
    { if (!OperatingSystem.IsWindows()) Skip = "Requires actual Windows named-pipe tokens and SCM; never installs a service."; }
}
