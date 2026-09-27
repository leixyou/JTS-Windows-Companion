using System.ComponentModel;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Windows.Diagnostics;

namespace JTS.WindowsCompanion.Tests;

public sealed class CompanionTerminalFailureDiagnosticTests
{
    [Fact]
    public void Win32FailureContainsOnlyStableNumericCodes()
    {
        var failure = new Win32Exception(233, "secret path C:\\private\\credential.txt");
        failure.Data["payload"] = "private-command";
        var diagnostic = CompanionTerminalFailureDiagnostic.Describe(failure);

        Assert.Equal("type=Win32Exception nativeErrorCode=233 hresult=0x80004005", diagnostic);
        Assert.DoesNotContain("secret", diagnostic);
        Assert.DoesNotContain("private", diagnostic);
    }

    [Fact]
    public void KnownProtocolFailureKeepsOnlyAnAllowlistedCode()
    {
        var diagnostic = CompanionTerminalFailureDiagnostic.Describe(
            new CompanionProtocolException("DVC_PDU_FLAGS_INVALID", "secret protocol payload"));

        Assert.Equal("type=CompanionProtocolException protocolCode=DVC_PDU_FLAGS_INVALID hresult=0x80131500", diagnostic);
        Assert.DoesNotContain("secret", diagnostic);
    }

    [Fact]
    public void UnknownProtocolCodeCannotInjectOrLeakText()
    {
        foreach (var code in new[] { "PRIVATE_SECRET", "DVC_PDU_FLAGS_INVALID\nprivate", new string('X', 100_000) })
        {
            var diagnostic = CompanionTerminalFailureDiagnostic.Describe(
                new CompanionProtocolException(code, "secret protocol payload"));

            Assert.Equal("type=CompanionProtocolException protocolCode=UNCLASSIFIED hresult=0x80131500", diagnostic);
            Assert.True(diagnostic.Length < 128);
        }
    }

    [Fact]
    public void UnknownExceptionDoesNotReadMessageOrToString()
    {
        var diagnostic = CompanionTerminalFailureDiagnostic.Describe(new SensitiveException());

        Assert.Equal("type=Exception hresult=0x80131500", diagnostic);
    }

    private sealed class SensitiveException : Exception
    {
        public override string Message => throw new InvalidOperationException("Must not read private error text.");
        public override string ToString() => throw new InvalidOperationException("Must not format private error text.");
    }
}
