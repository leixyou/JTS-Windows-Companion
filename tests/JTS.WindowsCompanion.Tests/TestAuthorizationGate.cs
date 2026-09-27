using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.Tests;

internal sealed class TestAuthorizationGate : ICompanionAuthorizationGate
{
    public TestAuthorizationGate(bool authorized = true, string authorizationScope = "test-peer")
    {
        IsAuthorized = authorized;
        AuthorizationScope = authorizationScope;
    }

    public bool IsAuthorized { get; set; }

    public string AuthorizationScope { get; set; }

    public CompanionAuthorizationDecision Evaluate(string method)
    {
        var bootstrap = method is "companion.hello" or "companion.authorize" or "companion.state";
        if (bootstrap)
        {
            return new CompanionAuthorizationDecision(true, true, null);
        }

        return IsAuthorized
            ? new CompanionAuthorizationDecision(true, false, AuthorizationScope)
            : new CompanionAuthorizationDecision(false, false, null);
    }

    public void ResetSession()
    {
        // Tests opt into a fixed authorization state explicitly. Production uses
        // CompanionAuthorizationSession, whose reset clears the live peer.
    }
}
