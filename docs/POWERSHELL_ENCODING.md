# PowerShell pipe encoding

The current-user DVC executor and approved elevation executor share
`PowerShellUtf8LaunchPlan`. Both sides of stdin, stdout and stderr explicitly use
UTF-8 without a byte-order mark. A constant UTF-16LE `-EncodedCommand` bootstrap
initializes the child encodings before reading the user script from stdin.
The user script is never placed in command-line arguments, environment variables
or a temporary script file. This supports Unicode literals and identifiers as
well as Unicode PowerShell output on Windows PowerShell 5.1.

The bootstrap keeps the user's error preference unchanged, requests text output
instead of CLIXML, and reports a failed final command or terminating exception as
exit 1. An explicit `exit N` remains the script's exit code. The launch still uses
`-NoProfile` and `-NonInteractive`, and does not bypass execution policy.
Existing authorization, cancellation, process containment and byte-output limits
remain owned by their respective executors.

`PowerShellUtf8Tests` includes real Windows child-process checks for Unicode
script input, stdout, stderr, explicit exit codes, nonterminating and terminating
errors, and UTF-8 byte-output limits. These native cases are skipped on macOS;
the cross-platform launch-plan check is not Windows acceptance. The approved
broker test uses a test approval verifier to exercise the real Job Object process
path; it does not claim to test interactive UAC consent.

GitHub Windows CI runs this scope and preserves its TRX under
`windows-powershell-utf8`. The separate independent relay executor already has
its own UTF-8 bootstrap and is unchanged by this correction.
