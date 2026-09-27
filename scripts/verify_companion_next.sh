#!/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/verify_companion_next.sh relay|runtime|pairing|control|execution|worker-ipc|worker-service|authority-service|authority-provisioner|unattended-installation [--list|--restore-only]

Explicitly select one isolated Next module; no default/all scope exists.
  --list          Show selected projects and requirements without invoking dotnet.
  --restore-only  Verify locked dependencies without building or running tests.
  (no option)    Locked restore, then only the selected module's Debug tests.

JTS_DOTNET may name an absolute dotnet executable. Otherwise use dotnet on PATH.
Relay:   .NET SDK 8+ and the selected host's .NET 8 runtime for test execution.
Runtime: .NET SDK 10+ and the selected host's .NET 10 runtime for test execution.
Pairing: .NET SDK 10+ and the selected host's .NET 10 runtime for test execution.
Control: .NET SDK 10+ and the selected host's .NET 10 runtime for test execution.
Execution: .NET SDK 10+ / runtime 10; real Windows tests require explicit opt-in.
Worker IPC: .NET SDK 10+ / runtime 10; also builds the one-shot WorkerRunner.
Worker service: .NET SDK 10+ / runtime 10; no actual SCM/account installation is performed.
Authority service: .NET SDK 10+ / runtime 10; builds the SCM entry point without installing/starting it.
Authority provisioner: .NET SDK 10+ / runtime 10; portable staging tests, no account/service provisioning.
Unattended installation: .NET SDK 10+ / runtime 10; portable transaction/contract tests, no actual installation.
The combined Next .slnx requires SDK 10+. No major runtime roll-forward is set.
No 2.0, UI, service-installation, deployed-server or release gates are invoked.
EOF
}

fail() { printf 'ERROR: %s\n' "$1" >&2; exit 2; }

if [[ $# -eq 1 && ( "$1" == "--help" || "$1" == "-h" ) ]]; then usage; exit 0; fi
[[ $# -ge 1 && $# -le 2 ]] || { usage >&2; exit 2; }
next_scope="$1"
next_mode="${2:-test}"
case "$next_mode" in test|--list|--restore-only) ;; *) fail "Unknown option: $next_mode" ;; esac
case "$next_scope" in
  relay) next_module="Relay"; next_framework_major=8 ;;
  runtime) next_module="Runtime"; next_framework_major=10 ;;
  pairing) next_module="Pairing"; next_framework_major=10 ;;
  control) next_module="Control"; next_framework_major=10 ;;
  execution) next_module="Execution"; next_framework_major=10 ;;
  worker-ipc) next_module="WorkerIpc"; next_framework_major=10 ;;
  worker-service) next_module="WorkerService"; next_framework_major=10 ;;
  authority-service) next_module="AuthorityService"; next_framework_major=10 ;;
  authority-provisioner) next_module="AuthorityProvisioner"; next_framework_major=10 ;;
  unattended-installation) next_module="UnattendedInstallation"; next_framework_major=10 ;;
  *) fail "Select exactly one scope: relay, runtime, pairing, control, execution, worker-ipc, worker-service, authority-service, authority-provisioner or unattended-installation." ;;
esac

next_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
next_source="$next_root/src/JTS.WindowsCompanion.$next_module/JTS.WindowsCompanion.$next_module.csproj"
next_tests="$next_root/tests/JTS.WindowsCompanion.$next_module.Tests/JTS.WindowsCompanion.$next_module.Tests.csproj"
next_results="$next_root/tests/JTS.WindowsCompanion.$next_module.Tests/TestResults"
for next_project in "$next_source" "$next_tests"; do
  [[ -f "$next_project" && -f "${next_project%/*}/packages.lock.json" ]] \
    || fail "A selected project or its reviewed packages.lock.json is missing."
done

if [[ "$next_mode" == "--list" ]]; then
  printf 'Scope: %s\nSource: %s\nTests: %s\nSDK: %s+\nTest runtime: net%s.0\n' \
    "$next_scope" "$next_source" "$next_tests" "$next_framework_major" "$next_framework_major"
  exit 0
fi

next_dotnet="${JTS_DOTNET:-}"
if [[ -z "$next_dotnet" ]]; then next_dotnet="$(command -v dotnet || true)"; fi
[[ "$next_dotnet" == /* && -x "$next_dotnet" && ! -d "$next_dotnet" ]] \
  || fail "Set JTS_DOTNET to an absolute, executable dotnet path."
next_sdk_version="$("$next_dotnet" --version)"
[[ "$next_sdk_version" =~ ^([0-9]+)\. ]] || fail "Cannot determine the selected .NET SDK version."
[[ "${BASH_REMATCH[1]}" -ge "$next_framework_major" ]] \
  || fail "$next_scope requires .NET SDK $next_framework_major or newer."

# Do not silently execute net8.0 tests using a different major runtime.
if [[ "$next_mode" == "test" ]]; then
  next_runtime_found=false
  while IFS= read -r next_runtime; do
    if [[ "$next_runtime" == "Microsoft.NETCore.App $next_framework_major."* ]]; then next_runtime_found=true; fi
  done < <("$next_dotnet" --list-runtimes)
  [[ "$next_runtime_found" == true ]] \
    || fail "The selected dotnet host needs its .NET $next_framework_major runtime; use another JTS_DOTNET or install that runtime."
fi

printf 'Locked restore: %s (SDK %s)\n' "$next_scope" "$next_sdk_version"
"$next_dotnet" restore "$next_tests" --locked-mode --nologo
[[ "$next_mode" != "--restore-only" ]] || exit 0

"$next_dotnet" test "$next_tests" --configuration Debug --no-restore --nologo \
  --logger "trx;LogFileName=companion-next-$next_scope.trx" --results-directory "$next_results"
