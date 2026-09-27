# Real Windows RDP + Companion QA runbook

This is the canonical real-machine runbook. Generate a fresh source archive
from the final clean commit for every run; timestamped copies under
`build/release-evidence` are historical evidence and must not be edited in
place. The authorized-lab path uses a fresh project P-256 diagnostic key and
does not import certificates or require Authenticode. It produces engineering
evidence, not production-artifact acceptance. Administrator/UAC remains enabled;
see [distribution policy](DISTRIBUTION_POLICY.md).

Run the complete procedure twice: once on a clean, supported Windows 10 x64
interactive test account and once on a clean Windows 11 x64 interactive test
account. Use a different `RUN_ID` and evidence directory for each operating
system. A pass on one Windows version cannot stand in for the other.

## 1. Prepare and serve the final Companion source on the Mac

Run from a clean final JTS-Windows-Companion checkout. The Mac client lives in the separate [JTS-Terminal-2.0 repository](https://github.com/leixyou/JTS-Terminal-2.0); run any Mac application build or client test commands from that checkout. The block defaults `JTS_REPO_ROOT` to the
current directory and `JTS_EVIDENCE_ROOT` below that checkout; override either
when the checkout or evidence volume lives elsewhere. Set
`JTS_EVIDENCE_SERVE_HOST` to the Mac LAN address reachable from the Windows
host and `JTS_RDP_TARGET_ENDPOINT` to the saved LAN target as `host:port`.
Record every printed parameter in the evidence summary. Leave the HTTP
server open only until the Windows download completes.

```sh
set -euo pipefail
REPO_ROOT="${JTS_REPO_ROOT:-$PWD}"
SERVE_HOST="${JTS_EVIDENCE_SERVE_HOST:?Set this to the Mac LAN address reachable from Windows}"
SERVE_PORT="${JTS_EVIDENCE_SERVE_PORT:-8765}"
RDP_TARGET_ENDPOINT="${JTS_RDP_TARGET_ENDPOINT:?Set this to the saved LAN RDP target as host:port}"
EVIDENCE_ROOT="${JTS_EVIDENCE_ROOT:-$REPO_ROOT/build/release-evidence/rdp-2.0}"
cd "$REPO_ROOT"
git diff --quiet -- .
git diff --cached --quiet -- .
test -z "$(git status --porcelain --untracked-files=all -- .)"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
SOURCE_COMMIT="$(git rev-parse HEAD)"
SOURCE_TREE="$(git rev-parse HEAD^{tree})"
SHORT_COMMIT="$(git rev-parse --short=7 HEAD)"
OUTPUT="$EVIDENCE_ROOT/$RUN_ID/windows-companion-preflight"
MAC_RESULT_ROOT="${JTS_MAC_RESULT_ROOT:-$EVIDENCE_ROOT/$RUN_ID/rdp-companion}"
ZIP_NAME="JTS-Windows-Companion-$SHORT_COMMIT.zip"
mkdir -p "$OUTPUT" "$MAC_RESULT_ROOT"
git archive --format=zip --prefix=JTS-Windows-Companion/ \
  --output="$OUTPUT/$ZIP_NAME" "$SOURCE_COMMIT" .
ZIP_SHA256="$(shasum -a 256 "$OUTPUT/$ZIP_NAME" | awk '{print $1}')"
printf 'RUN_ID=%s\nSOURCE_COMMIT=%s\nSOURCE_TREE=%s\nZIP_NAME=%s\nZIP_SHA256=%s\nSERVE_HOST=%s\nSERVE_PORT=%s\nRDP_TARGET_ENDPOINT=%s\nMAC_RESULT_ROOT=%s\n' \
  "$RUN_ID" "$SOURCE_COMMIT" "$SOURCE_TREE" "$ZIP_NAME" "$ZIP_SHA256" \
  "$SERVE_HOST" "$SERVE_PORT" "$RDP_TARGET_ENDPOINT" "$MAC_RESULT_ROOT"
cd "$OUTPUT"
/usr/bin/python3 -m http.server "$SERVE_PORT" --bind "$SERVE_HOST"
```

## 2. Build, manifest-verify, install, and verify on the Windows host

Run in a normal, non-administrator Windows PowerShell inside the same RDP user
session. The script modifies this user's Local AppData installation, HKCU
startup/uninstall entries, and test state, not Windows certificate stores.

```powershell
$ErrorActionPreference = 'Stop'
$runId = '<RUN_ID from the Mac>'
$sourceCommit = '<SOURCE_COMMIT from the Mac>'
$sourceTree = '<SOURCE_TREE from the Mac>'
$zipName = '<ZIP_NAME from the Mac>'
$zipSha256 = '<ZIP_SHA256 from the Mac>'
$macEvidenceHost = '<SERVE_HOST from the Mac>'
$macEvidencePort = [int]'<SERVE_PORT from the Mac>'
if ($runId -notmatch '\A[0-9]{8}T[0-9]{6}Z\z' -or
    $sourceCommit -notmatch '\A[0-9a-f]{40}\z' -or
    $sourceTree -notmatch '\A[0-9a-f]{40}\z' -or
    $zipSha256 -notmatch '\A[0-9a-f]{64}\z' -or
    $zipName -notmatch '\A[A-Za-z0-9_.-]+\.zip\z' -or
    $macEvidenceHost -notmatch '\A[0-9A-Za-z.-]+\z' -or
    $macEvidencePort -lt 1 -or $macEvidencePort -gt 65535) {
    throw 'The recorded source identity is invalid.'
}
$base = Join-Path $env:USERPROFILE ("Downloads\jts-wc-{0}" -f $sourceCommit.Substring(0, 7))
$zip = "$base.zip"
$url = "http://${macEvidenceHost}:$macEvidencePort/$zipName"
Invoke-WebRequest -Uri $url -OutFile $zip
$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLowerInvariant()
if ($actual -ne $zipSha256.ToLowerInvariant()) {
    throw "Source ZIP hash mismatch: $actual"
}
if (Test-Path -LiteralPath $base) {
    Remove-Item -LiteralPath $base -Recurse -Force
}
Expand-Archive -LiteralPath $zip -DestinationPath $base -Force
Set-Location (Join-Path $base 'JTS-Windows-Companion')

$evidence = Join-Path $env:USERPROFILE "Documents\JTS-Evidence\$runId"
New-Item -ItemType Directory -Path "$evidence\candidate" -Force | Out-Null
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-authorized-lab-setup.ps1 `
    -OutputDirectory "$evidence\candidate"

$candidate = Join-Path $evidence 'candidate\JTS-Windows-Companion-2.0.0-win-x64-AUTHORIZED-LAB-ONLY.exe'
$installer = Start-Process -FilePath $candidate -ArgumentList @('--install', '--quiet') -PassThru
$installer.WaitForExit()
$installer.Refresh()
if ($installer.ExitCode -ne 0) { throw "Companion Setup failed: $($installer.ExitCode)" }

$install = Join-Path $env:LOCALAPPDATA 'Programs\JTS Terminal\Windows Companion'
$paths = @(
    (Join-Path $install 'JTS.WindowsCompanion.Agent.exe'),
    (Join-Path $install 'JTS.WindowsCompanion.UacBroker.exe'),
    (Join-Path $install 'JTS.WindowsCompanion.Setup.exe')
)
$signatureFiles = @(
    [pscustomobject]@{ role = 'candidate-setup'; path = $candidate },
    [pscustomobject]@{ role = 'installed-agent'; path = $paths[0] },
    [pscustomobject]@{ role = 'installed-uac-broker'; path = $paths[1] },
    [pscustomobject]@{ role = 'installed-setup'; path = $paths[2] }
)
. .\scripts\windows-companion-evidence.ps1
$authenticodeEvidence = @($signatureFiles | ForEach-Object {
    Get-JTSAuthenticodeEvidence -Role $_.role -Path $_.path
})
$signToolEvidence = @() # Optional Authenticode profile only; unsigned is expected here.
$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$agent = @(Get-CimInstance Win32_Process -Filter "Name='JTS.WindowsCompanion.Agent.exe'" |
    Where-Object { $_.ExecutablePath -eq $paths[0] })
if ($agent.Count -ne 1) { throw 'Exactly one installed current-user Agent was not found.' }
$network = Get-JTSCompanionNetworkSnapshot `
    -Stage 'installed-idle' `
    -ExecutablePaths @($signatureFiles.path) `
    -ExpectedRunningPaths @($paths[0]) `
    -ExpectedAbsentPaths @($candidate, $paths[1], $paths[2]) `
    -ExpectedOwnerSid $currentSid
Assert-JTSCompanionOwnsNoNetworkEndpoints -Snapshot $network
$jtsServices = @(Get-Service -ErrorAction Stop | Where-Object {
    $_.Name -like '*JTS*' -or $_.DisplayName -like '*JTS*'
})
$jtsFirewallRules = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object {
    $_.DisplayName -like '*JTS*Windows*Companion*'
})
$machineUninstallKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\JTSWindowsCompanion',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\JTSWindowsCompanion'
)
$presentMachineUninstallKeys = @($machineUninstallKeys | Where-Object {
    Test-Path -LiteralPath $_ -ErrorAction Stop
})
$hkcuUninstall = Test-Path `
    -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\JTSWindowsCompanion' `
    -ErrorAction Stop
if (-not $hkcuUninstall) {
    throw 'The current-user uninstall registration is missing.'
}
if ($jtsServices.Count -ne 0 -or $jtsFirewallRules.Count -ne 0 -or
    $presentMachineUninstallKeys.Count -ne 0) {
    throw 'The current-user package added machine-wide service, firewall, or HKLM state.'
}
$report = [ordered]@{
    capturedAtUtc = [DateTime]::UtcNow.ToString('o')
    sourceCommit = $sourceCommit
    windowsCompanionTree = $sourceTree
    sourceZip = $zipName
    sourceZipSha256 = $zipSha256
    windows = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber
    candidateSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $candidate).Hash.ToLowerInvariant()
    authenticodeEvidence = $authenticodeEvidence
    signToolEvidence = $signToolEvidence
    networkSnapshots = @($network)
    agentProcessId = $agent[0].ProcessId
    agentOwnerSid = $currentSid
    hkcuUninstall = $hkcuUninstall
    jtsServiceCount = $jtsServices.Count
    jtsFirewallRuleCount = $jtsFirewallRules.Count
    presentMachineUninstallKeys = $presentMachineUninstallKeys
}
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath "$evidence\windows-install-preflight.json" -Encoding UTF8
if (($authenticodeEvidence | Where-Object { $_.signatureStatus -ne 'Valid' }) -or
    @($authenticodeEvidence.signerCertificate.thumbprint | Select-Object -Unique).Count -ne 1) {
    throw 'Installed Agent, Broker, and Setup do not have one valid signer.'
}
```

For the optional Authenticode profile only,
`signature-evidence\signtool-*.log` contains native `/pa /all /v` policy
verification only when `signtool.exe` was resolved below the canonical Windows
Kits directory and the tool itself had a valid Microsoft Authenticode signature.
The evidence records the tool SHA-256, signer, thumbprint, original filename,
and product version and rechecks that identity before and after every
invocation. Each native verification log is bound into the evidence by its
byte length and SHA-256 and is rejected if it is missing, rewritten, or a
reparse point. The exact input executable length and SHA-256 are captured
before and after the native invocation, must remain unchanged, and must match
the Authenticode record and pre-registered role manifest. A log saying that trusted
`signtool.exe` is unavailable is explicit incomplete evidence, not a production
signature pass. The default diagnostic run uses no Authenticode certificate;
`NotSigned` and no timestamp are expected and do not block its manifest checks.
Only the optional production Authenticode profile requires a valid public
signer and non-null timestamp certificate.

If `dotnet --info` is unavailable, install the .NET 8 SDK first through the
normal Microsoft installer or this user-confirmed `winget` command, then rerun
the block:

```powershell
winget install --exact --id Microsoft.DotNet.SDK.8 --source winget --accept-source-agreements --accept-package-agreements
```

The short path preserves the separate DPAPI pairing/state directory and leaves
the current-user Agent installed and running. Primary Windows evidence:

```text
  %USERPROFILE%\Documents\JTS-Evidence\<RUN_ID>\
  candidate\build-evidence.json
  candidate\JTS.WindowsCompanion.release.json
  candidate\JTS.WindowsCompanion.release-public.pem
  windows-install-preflight.json
```

The build snapshot records the diagnostic release identity, exact candidate and
payload hashes, manifest and public-key digests, and private-key cleanup. It is
bound before installation; editable adjacent hashes are not an independent
publisher identity. Authenticode metadata above is informational and may say
`NotSigned`.

### Optional destructive installer/recovery matrix

Run the full repository QA only on a resettable test account after explicitly
accepting that it starts with `--purge-data`, removes the current user's prior
Companion identity/pairing state, and performs repeated install/uninstall and
forced-termination cycles:

```powershell
$fullEvidence = Join-Path $env:USERPROFILE "Documents\JTS-Evidence\$runId-full-setup-qa"
$elevationWorking = Join-Path $evidence 'elevation-protocol-working'
New-Item -ItemType Directory -Path $elevationWorking -Force | Out-Null
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-authorized-lab-qa.ps1 `
    -OutputRoot $fullEvidence `
    -RequireInteractiveUIA `
    -RequireInteractiveConsent `
    -RequireInteractiveUAC `
    -ElevationWorkingDirectory $elevationWorking
```

That optional run emits `authorized-lab-run-summary.json`, the full transcript,
`evidence\test-results\windows-companion-release.trx`, and
`authorized-lab-setup-qa.json`, then leaves a newly installed Agent ready for
the RDP/DVC checks below. `-RequireInteractiveUIA` makes the runner fail unless
the exact independent-child integration test passes. `-RequireInteractiveConsent`
separately requires both Companion consent-dialog tests. `-RequireInteractiveUAC`
does not reuse either TRX result: it builds an exact-name elevation QA peer and
Broker with one fresh diagnostic key and manifest, launches that Broker through
Windows `runas` twice, and fails unless schema-3 evidence proves locked-image
manifest verification, exact marker execution, four tamper rejections, lease expiry,
and natural zero-code Broker exit. With all three switches, the TRX has zero
skipped tests and `evidence\signed-elevation-protocol\evidence\elevation-protocol-qa.json`
contains the real UAC protocol proof.
Detached-Setup evidence additionally requires the live executable to be in one
direct `%TEMP%\JTS-Windows-Companion-Setup-<32-hex>` root with the exact product
ownership marker and the same SHA-256 as the candidate/installed Setup captured
before installation. The temporary copy must not introduce different bytes.

## 3. Prepare bounded file fixtures on Windows

Keep the same normal-user PowerShell open. The positive fixture stays under the
installed `documents` root. The outside sentinel is deliberately under Local
AppData, outside every configured file root. The junction provides a real
Windows reparse-point negative case without requiring administrator rights.

```powershell
$runtimeRoot = Join-Path $evidence 'runtime-mcp'
$filesRoot = Join-Path $runtimeRoot 'files'
$outsideRoot = Join-Path $env:LOCALAPPDATA "JTSTerminal\WindowsCompanion-QA-Outside-$runId"
$junctionPath = Join-Path $filesRoot 'outside-junction'
$transferRoot = Join-Path $env:LOCALAPPDATA 'JTSTerminal\WindowsCompanion\Transfers'
New-Item -ItemType Directory -Path $filesRoot, $outsideRoot -Force | Out-Null
if (Test-Path -LiteralPath $junctionPath) {
    (Get-Item -LiteralPath $junctionPath -Force).Delete()
}
$junction = New-Item -ItemType Junction -Path $junctionPath -Target $outsideRoot
if (($junction.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
    throw 'The Windows junction fixture is not a reparse point.'
}

$inlineBytes = [Text.Encoding]::UTF8.GetBytes("JTS_COMPANION_INLINE_OK`r`n")
$largeBytes = New-Object byte[] (600 * 1024)
for ($index = 0; $index -lt $largeBytes.Length; $index++) {
    $largeBytes[$index] = ($index * 31 + 17) % 251
}
$rangeOffset = 131071
$rangeLength = 262177
$rangeBytes = New-Object byte[] $rangeLength
[Array]::Copy($largeBytes, $rangeOffset, $rangeBytes, 0, $rangeLength)
function Get-ByteArraySha256 {
    param([Parameter(Mandatory)] [byte[]] $Bytes)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return (($hasher.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $hasher.Dispose()
    }
}
$sentinelPath = Join-Path $outsideRoot 'outside-sentinel.bin'
[IO.File]::WriteAllBytes($sentinelPath, [Text.Encoding]::UTF8.GetBytes('OUTSIDE_ROOT_MUST_NOT_CHANGE'))
$fixture = [ordered]@{
    rootId = 'documents'
    relativeRoot = "JTS-Evidence\$runId\runtime-mcp\files"
    inlineLength = $inlineBytes.Length
    inlineSha256 = Get-ByteArraySha256 -Bytes $inlineBytes
    largeLength = $largeBytes.Length
    largeSha256 = Get-ByteArraySha256 -Bytes $largeBytes
    rangeOffset = $rangeOffset
    rangeLength = $rangeLength
    rangeSha256 = Get-ByteArraySha256 -Bytes $rangeBytes
    outsideSentinelPath = $sentinelPath
    outsideSentinelSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $sentinelPath).Hash.ToLowerInvariant()
    junctionPath = $junctionPath
    transferRoot = $transferRoot
}
$fixture | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath "$runtimeRoot\file-fixture.json" -Encoding UTF8
$runtimeNetworkSnapshots = New-Object Collections.Generic.List[object]
$runtimeMonitoredPaths = @($candidate) + @($paths)
function Add-RuntimeNetworkSnapshot {
    param([Parameter(Mandatory)] [string] $Stage)
    $snapshot = Get-JTSCompanionNetworkSnapshot `
        -Stage $Stage `
        -ExecutablePaths $runtimeMonitoredPaths `
        -ExpectedRunningPaths @($paths[0]) `
        -ExpectedAbsentPaths @($candidate, $paths[1], $paths[2]) `
        -ExpectedOwnerSid $currentSid
    Assert-JTSCompanionOwnsNoNetworkEndpoints -Snapshot $snapshot
    $runtimeNetworkSnapshots.Add($snapshot)
}
Add-RuntimeNetworkSnapshot -Stage 'before-live-dvc-file-matrix'
```

Create the exact upload bytes on the Mac without printing the 800 KiB base64
payload into a transcript:

```sh
python3 - <<'PY'
import base64, hashlib, json
from pathlib import Path

data = bytes((index * 31 + 17) % 251 for index in range(600 * 1024))
inline = b"JTS_COMPANION_INLINE_OK\r\n"
offset, length = 131071, 262177
result = {
    "inlineContentBase64": base64.b64encode(inline).decode("ascii"),
    "inlineSha256": hashlib.sha256(inline).hexdigest(),
    "largeContentBase64": base64.b64encode(data).decode("ascii"),
    "largeSha256": hashlib.sha256(data).hexdigest(),
    "rangeSha256": hashlib.sha256(data[offset:offset + length]).hexdigest(),
}
Path("/tmp/jts-companion-file-fixture.json").write_text(json.dumps(result), encoding="utf-8")
PY
chmod 600 /tmp/jts-companion-file-fixture.json
```

## 4. Complete the live DVC and file-operation matrix

1. Open the saved `<RDP_TARGET_ENDPOINT printed by step 1>` LAN RDP target and make the
   certificate trust decision in JTS Terminal. Record that endpoint in the
   private evidence summary; do not bake it into this reusable runbook.
2. Confirm the Companion pairing fingerprint on Windows.
3. Grant the registered MCP client the required Observe, Control, Command, and
   Files scopes in JTS Terminal.
4. Retain every structured request/response under the Mac evidence directory.
   Do not paste the large `contentBase64` field into the human-readable summary.

Start with the connection proof:

```text
jts_list_targets {}
jts_open_desktop {"targetId":"<targetId>","deadlineMs":60000}
jts_desktop_status {"targetId":"<targetId>","sessionId":"<sessionId>"}
jts_desktop_observe {"targetId":"<targetId>","sessionId":"<sessionId>"}
jts_windows_exec {"targetId":"<targetId>","sessionId":"<sessionId>","rootId":"documents","cwd":".","deadlineMs":30000,"command":"Write-Output 'JTS_COMPANION_E2E_OK'; Write-Output ([Environment]::OSVersion.VersionString); Write-Output $PSVersionTable.PSVersion.ToString()"}
jts_windows_files {"targetId":"<targetId>","sessionId":"<sessionId>","operation":"list","rootId":"documents","path":"JTS-Evidence\\<RUN_ID>\\runtime-mcp\\files"}
```

Record the `sessionId` returned by `jts_open_desktop`. Every desktop and
Companion command below must use that exact currently connected session.
Companion tools never open RDP implicitly. After any close or reconnect, call
`jts_open_desktop` again when necessary and replace `<sessionId>` with the new
returned value before issuing another Companion command.

Retain the complete structured responses for both calls. Each successful
`jts_windows_exec` and `jts_windows_files` response must contain
`transportProof.channel=companion-dvc`. Capture `jts_desktop_status` immediately
before and after the pair, and capture the Agent PID, owner SID, start time,
executable SHA-256, and post-hash zero-endpoint evidence with
`Add-RuntimeNetworkSnapshot`. Each endpoint record must cover a monotonic
stability window of at least 2,000 ms, with repeated TCP/UDP samples separated
by bounded waits of up to 250 ms plus a separate terminal sample. The exact PID,
executable path, and process start identity must be revalidated after every
sample, including the terminal sample; a query failure, identity change, or
endpoint-set drift invalidates the record. This proves only the recorded bounded
interval. Together these records form the bounded DVC trace; text output or a
screenshot by itself is not DVC evidence.

Then execute all positive file operations. Substitute the two base64 values
from `/tmp/jts-companion-file-fixture.json` programmatically:

```text
jts_windows_files {"targetId":"<targetId>","sessionId":"<sessionId>","operation":"write","rootId":"documents","path":"JTS-Evidence\\<RUN_ID>\\runtime-mcp\\files\\inline.txt","contentBase64":"<inlineContentBase64>","overwrite":false}
jts_windows_files {"targetId":"<targetId>","sessionId":"<sessionId>","operation":"stat","rootId":"documents","path":"JTS-Evidence\\<RUN_ID>\\runtime-mcp\\files\\inline.txt"}
jts_windows_files {"targetId":"<targetId>","sessionId":"<sessionId>","operation":"read","rootId":"documents","path":"JTS-Evidence\\<RUN_ID>\\runtime-mcp\\files\\inline.txt"}
jts_windows_files {"targetId":"<targetId>","sessionId":"<sessionId>","operation":"upload","rootId":"documents","path":"JTS-Evidence\\<RUN_ID>\\runtime-mcp\\files\\large.bin","contentBase64":"<largeContentBase64>","overwrite":false,"deadlineMs":60000}
jts_windows_files {"targetId":"<targetId>","sessionId":"<sessionId>","operation":"stat","rootId":"documents","path":"JTS-Evidence\\<RUN_ID>\\runtime-mcp\\files\\large.bin"}
jts_windows_files {"targetId":"<targetId>","sessionId":"<sessionId>","operation":"download","rootId":"documents","path":"JTS-Evidence\\<RUN_ID>\\runtime-mcp\\files\\large.bin","offset":0,"length":614400,"deadlineMs":60000}
jts_windows_files {"targetId":"<targetId>","sessionId":"<sessionId>","operation":"download","rootId":"documents","path":"JTS-Evidence\\<RUN_ID>\\runtime-mcp\\files\\large.bin","offset":131071,"length":262177,"deadlineMs":60000}
```

Required assertions are exact decoded bytes for `read`, exact length and
SHA-256 for both `stat` calls, a 614400-byte upload/download with the fixture's
`largeSha256`, and a 262177-byte range with `rangeSha256`. A successful status
or byte count without decoding and hashing the returned content is insufficient.

Run the negative matrix. `..\outside.bin` must return `PATH_TRAVERSAL`, the
absolute path must return `PATH_ABSOLUTE`, and every operation through the real
junction must return `REPARSE_POINT_REJECTED`:

```text
jts_windows_files {"targetId":"<targetId>","sessionId":"<sessionId>","operation":"stat","rootId":"documents","path":"..\\outside.bin"}
jts_windows_files {"targetId":"<targetId>","sessionId":"<sessionId>","operation":"stat","rootId":"documents","path":"C:\\Windows\\win.ini"}
jts_windows_files {"targetId":"<targetId>","sessionId":"<sessionId>","operation":"list","rootId":"documents","path":"JTS-Evidence\\<RUN_ID>\\runtime-mcp\\files\\outside-junction"}
jts_windows_files {"targetId":"<targetId>","sessionId":"<sessionId>","operation":"stat","rootId":"documents","path":"JTS-Evidence\\<RUN_ID>\\runtime-mcp\\files\\outside-junction\\outside-sentinel.bin"}
jts_windows_files {"targetId":"<targetId>","sessionId":"<sessionId>","operation":"read","rootId":"documents","path":"JTS-Evidence\\<RUN_ID>\\runtime-mcp\\files\\outside-junction\\outside-sentinel.bin"}
jts_windows_files {"targetId":"<targetId>","sessionId":"<sessionId>","operation":"write","rootId":"documents","path":"JTS-Evidence\\<RUN_ID>\\runtime-mcp\\files\\outside-junction\\write.bin","contentBase64":"<inlineContentBase64>","overwrite":false}
jts_windows_files {"targetId":"<targetId>","sessionId":"<sessionId>","operation":"upload","rootId":"documents","path":"JTS-Evidence\\<RUN_ID>\\runtime-mcp\\files\\outside-junction\\upload.bin","contentBase64":"<inlineContentBase64>","overwrite":false}
jts_windows_files {"targetId":"<targetId>","sessionId":"<sessionId>","operation":"download","rootId":"documents","path":"JTS-Evidence\\<RUN_ID>\\runtime-mcp\\files\\outside-junction\\outside-sentinel.bin","offset":0,"length":16}
```

Back in Windows PowerShell, prove the negative calls did not mutate the outside
target and capture the active-DVC no-listener state:

```powershell
$fixture = Get-Content -LiteralPath "$runtimeRoot\file-fixture.json" -Raw | ConvertFrom-Json
$actualSentinelSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $fixture.outsideSentinelPath).Hash.ToLowerInvariant()
if ($actualSentinelSha256 -ne $fixture.outsideSentinelSha256) {
    throw 'A rejected root-escape operation changed the outside sentinel.'
}
if ((Test-Path -LiteralPath (Join-Path $outsideRoot 'write.bin')) -or
    (Test-Path -LiteralPath (Join-Path $outsideRoot 'upload.bin'))) {
    throw 'A rejected reparse-point operation created a file outside the allowed root.'
}
Add-RuntimeNetworkSnapshot -Stage 'after-live-dvc-file-matrix'
```

## 5. Prove DPAPI identity and pairing persistence

After pairing succeeds, record the encrypted files' hashes and ACLs and prove
that the current Windows user can decrypt both envelopes with the exact product
entropy. Never write, print, or add the decrypted bytes to evidence.

```powershell
$stateRoot = Join-Path $env:LOCALAPPDATA 'JTSTerminal\WindowsCompanion'
$identityPath = Join-Path $stateRoot 'identity.v1.json'
$pairedPeerPath = Join-Path $stateRoot 'paired-peer.v1.json'

function Test-JTSCurrentUserDpapiEnvelope {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $ProtectedProperty,
        [Parameter(Mandatory)] [string] $EntropyLabel
    )
    $protected = [byte[]]@()
    $entropy = [byte[]]@()
    $plaintext = [byte[]]@()
    try {
        $document = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json
        $protected = [Convert]::FromBase64String([string]$document.$ProtectedProperty)
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $entropy = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($EntropyLabel))
        } finally {
            $sha.Dispose()
        }
        $plaintext = [Security.Cryptography.ProtectedData]::Unprotect(
            $protected,
            $entropy,
            [Security.Cryptography.DataProtectionScope]::CurrentUser)
        if ($plaintext.Length -eq 0) { throw "DPAPI returned empty plaintext for $Path" }
        return [pscustomobject][ordered]@{
            path = $Path
            sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
            aclSddl = (Get-Acl -LiteralPath $Path -ErrorAction Stop).Sddl
            currentUserUnprotectSucceeded = $true
        }
    } finally {
        if ($protected.Length -gt 0) { [Array]::Clear($protected, 0, $protected.Length) }
        if ($entropy.Length -gt 0) { [Array]::Clear($entropy, 0, $entropy.Length) }
        if ($plaintext.Length -gt 0) { [Array]::Clear($plaintext, 0, $plaintext.Length) }
    }
}

$dpapiBaseline = @(
    Test-JTSCurrentUserDpapiEnvelope `
        -Path $identityPath `
        -ProtectedProperty 'ProtectedPrivateKeyBase64' `
        -EntropyLabel 'JTS.WindowsCompanion.Identity.v1'
    Test-JTSCurrentUserDpapiEnvelope `
        -Path $pairedPeerPath `
        -ProtectedProperty 'ProtectedGrantBase64' `
        -EntropyLabel 'JTS.WindowsCompanion.PairedPeer.v1'
)
$dpapiBaseline | ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath "$runtimeRoot\dpapi-current-user.json" -Encoding UTF8
```

Restart the installed Agent and reconnect the same RDP target. Then run a normal
installed-Setup repair, reconnect, perform a normal uninstall (without
`--purge-data`), reinstall the same candidate, and reconnect again. After each
boundary, repeat the two file hashes above and require both hashes to equal the
baseline. Require `jts_desktop_status` to return paired/ready and repeat the
small DVC `jts_windows_exec` proof after each reconnect. A new pairing prompt,
changed encrypted file hash, or manual copying of replacement state fails this
gate.

On both production-signing matrix machines, also copy the two encrypted JSON
files to a second standard test user's private directory and run the same
`ProtectedData.Unprotect(..., CurrentUser)` calls while signed in as that second
user. Both calls must fail cryptographically. Record only account SIDs, file
hashes, exception types, and `secondUserUnprotectSucceeded=false`; never record
credentials or decrypted data.

## 6. Prove UI Automation through tests and the public MCP surface

The full QA run's TRX must contain exactly one passed
`WindowsUiAutomationIntegrationTests.IndependentFixtureProcess_SupportsSnapshotFindSetValueInvokeAndWait`
result and zero skipped tests. That Windows-interactive test is the required
snapshot/find/setValue/invoke/wait integration proof against a dedicated child
process, not an in-process test window.

Separately, launch a test-owned Notepad process via `jts_windows_exec`, retain its PID,
and use the exact selector identities discovered for that process to exercise
the public MCP path. Substitute the real `stateRevision`, process ID,
automation ID/name, and controlled button selector; do not use a process that
was already open before the run. Call `jts_desktop_status` before each action
and substitute its newest `stateRevision`; a revision copied from an earlier
action is intentionally stale and must fail.

```text
jts_desktop_action {"targetId":"<targetId>","sessionId":"<sessionId>","action":"wait","expectedStateRevision":<stateRevision>,"selector":"{\"processId\":<notepadPid>,\"controlType\":\"Document\"}","deadlineMs":30000,"idempotencyKey":"<RUN_ID>-uia-wait"}
jts_desktop_action {"targetId":"<targetId>","sessionId":"<sessionId>","action":"semanticSetValue","expectedStateRevision":<stateRevision>,"selector":"{\"processId\":<notepadPid>,\"automationId\":\"<recorded-editor-automation-id>\"}","text":"JTS_UIA_E2E_OK","deadlineMs":30000,"idempotencyKey":"<RUN_ID>-uia-set"}
jts_desktop_action {"targetId":"<targetId>","sessionId":"<sessionId>","action":"semanticInvoke","expectedStateRevision":<stateRevision>,"selector":"{\"processId\":<notepadPid>,\"automationId\":\"<recorded-controlled-button-automation-id>\"}","deadlineMs":30000,"idempotencyKey":"<RUN_ID>-uia-invoke"}
```

Capture a fresh `jts_desktop_observe` after the value change and retain the
structured success for all three semantic calls. Any raw coordinate fallback,
OCR-only claim, skipped TRX result, or action against an unbound process is not
UI Automation evidence.

## 7. Prove interactive UAC and the elevation interlock

Follow [ELEVATION_AND_MANAGED_MODE.md](ELEVATION_AND_MANAGED_MODE.md). Start with
one bounded, idempotent elevated command whose only write scope is this run's
Documents evidence directory:

```text
jts_windows_exec {"targetId":"<targetId>","sessionId":"<sessionId>","rootId":"documents","cwd":"JTS-Evidence\\<RUN_ID>\\runtime-mcp","deadlineMs":120000,"command":"[IO.File]::WriteAllText((Join-Path (Get-Location) 'uac-approved.txt'), 'JTS_UAC_E2E_OK')","requiresElevation":true,"elevationDurationMs":150000,"elevationDataScopes":[{"rootId":"documents","relativePath":"JTS-Evidence\\<RUN_ID>\\runtime-mcp","access":"readWrite"}],"idempotencyKey":"<RUN_ID>-uac-accept"}
```

Accept the Companion consent and Windows UAC prompts as the human user. Require
`transportProof.channel=companion-dvc`, verify the exact marker bytes through
`jts_windows_files`, and require evidence that the action-bound elevation lease
was released immediately after the response.

Repeat with unique idempotency keys for: Companion decline
(`ELEVATION_DECLINED`), Windows UAC cancel (`UAC_CANCELLED`), and a deliberately
bounded UAC timeout (`UAC_TIMEOUT`). While the secure-desktop prompt is active,
issue one AI-originated `jts_desktop_action` and require the sensitive-interaction
interlock to reject it; then prove that local human mouse/keyboard input in the
JTS Terminal window can still accept or cancel the prompt. Never automate or
record a Windows password.

The `-RequireInteractiveUAC` authorized-lab gate above must also have retained
the issued lease/action digest and proved that changing each of the script,
working path, data scope, and timeout causes `NOT_AUTHORIZED`, with no marker
mutation. Its evidence must show two independently locked and
release-manifest-verified Broker sessions and natural zero-code exit after explicit
release.
Source unit tests or the two Companion consent-dialog tests alone do not close
this Windows UAC matrix.

## 8. Prove disconnect cleanup and reconnect isolation

This is deliberately a real connection interruption, not the same-channel
offset-retry unit test. Create a large bounded source, start its MCP download,
and issue `jts_close_desktop` from a second invocation while the first call is
still active. Do not delete transfer residue manually if the gate fails.

```powershell
$disconnectSource = Join-Path $filesRoot 'disconnect-source.bin'
$stream = [IO.File]::Open($disconnectSource, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
try { $stream.SetLength(64MB); $stream.Flush($true) } finally { $stream.Dispose() }
$preDisconnectSessions = @(Get-ChildItem -LiteralPath $transferRoot -Directory `
    -Filter 'session-*' -ErrorAction Stop)
if ($preDisconnectSessions.Count -ne 1) {
    throw "The disconnect test requires exactly one active session spool; found $($preDisconnectSessions.Count)."
}
$preDisconnectSessionRoot = $preDisconnectSessions[0].FullName
$baselinePartFiles = @(Get-ChildItem -LiteralPath $preDisconnectSessionRoot `
    -File -Filter '*.download.part' -ErrorAction Stop)
if ($baselinePartFiles.Count -ne 0) {
    throw 'The disconnect test must start without preexisting transfer part files.'
}
$disconnectObservation = Join-Path $runtimeRoot 'disconnect-part-observed.json'
Remove-Item -LiteralPath $disconnectObservation -Force -ErrorAction SilentlyContinue
$disconnectWatcher = Start-Job `
    -ArgumentList $preDisconnectSessionRoot, $disconnectObservation `
    -ScriptBlock {
    param($SessionRoot, $ObservationPath)
    $deadline = [DateTime]::UtcNow.AddSeconds(120)
    do {
        $part = Get-ChildItem -LiteralPath $SessionRoot -File `
            -Filter '*.download.part' -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 0 } |
            Select-Object -First 1
        if ($null -ne $part) {
            if ($part.DirectoryName -ne $SessionRoot) {
                throw 'The observed spool file is outside the active transfer session.'
            }
            if ($part.Name -notmatch '\A([0-9a-fA-F]{32})\.download\.part\z') {
                throw 'The observed spool file was not bound to one download transfer ID in the active session.'
            }
            [ordered]@{
                observedAtUtc = [DateTime]::UtcNow.ToString('o')
                sessionRoot = $SessionRoot
                transferId = $Matches[1].ToLowerInvariant()
                path = $part.FullName
                length = $part.Length
            } | ConvertTo-Json | Set-Content -LiteralPath $ObservationPath -Encoding UTF8
            return
        }
        Start-Sleep -Milliseconds 20
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'No in-flight Companion transfer spool file was observed.'
}
Add-RuntimeNetworkSnapshot -Stage 'before-forced-rdp-disconnect'
```

```text
# Invocation A: start and leave in flight.
jts_windows_files {"targetId":"<targetId>","sessionId":"<sessionId>","operation":"download","rootId":"documents","path":"JTS-Evidence\\<RUN_ID>\\runtime-mcp\\files\\disconnect-source.bin","offset":0,"length":67108864,"deadlineMs":120000}

# Invocation B: poll until the Windows watcher proves a non-empty .part file exists.
jts_windows_files {"targetId":"<targetId>","sessionId":"<sessionId>","operation":"stat","rootId":"documents","path":"JTS-Evidence\\<RUN_ID>\\runtime-mcp\\disconnect-part-observed.json"}

# Invocation C: run while A is still active.
jts_close_desktop {"targetId":"<targetId>","sessionId":"<sessionId>"}
```

Do not accept a run in which invocation A completed successfully before C, the
watcher marker was absent, or its observed length was zero. Repeat that attempt;
these conditions did not exercise interrupted-transfer cleanup. Retain the
Mac-side `file.download.begin` DVC trace for invocation A and require its
32-hex transfer ID to equal `disconnect-part-observed.json.transferId`; a spool
file merely observed somewhere under the transfer root is not bound evidence.

Reconnect the same target, confirm Companion pairing/ready state, and run the
following on Windows. The gate passes only if the old session spool is gone,
the new session has no `.part` files before another transfer, and no Companion
process owns a network endpoint. A stopped Agent, stale authorization, manual
spool deletion, or reuse of an old transfer ID is a failure to investigate.

```powershell
$deadline = [DateTime]::UtcNow.AddSeconds(60)
$disconnectObservationRecord = Get-Content -LiteralPath $disconnectObservation -Raw | ConvertFrom-Json
Receive-Job -Job $disconnectWatcher -Wait -AutoRemoveJob -ErrorAction Stop | Out-Null
if ($disconnectObservationRecord.length -le 0) {
    throw 'The disconnect watcher did not observe a non-empty transfer spool file.'
}
if ($disconnectObservationRecord.sessionRoot -ne $preDisconnectSessionRoot -or
    $disconnectObservationRecord.transferId -notmatch '\A[0-9a-f]{32}\z') {
    throw 'The disconnect observation is not bound to the expected session and transfer ID.'
}
do {
    $remainingPartFiles = @(Get-ChildItem -LiteralPath $transferRoot -Recurse `
        -File -Filter '*.part' -ErrorAction Stop)
    $postReconnectSessions = @(Get-ChildItem -LiteralPath $transferRoot -Directory `
        -Filter 'session-*' -ErrorAction Stop)
    if ($remainingPartFiles.Count -eq 0 -and
        -not (Test-Path -LiteralPath $preDisconnectSessionRoot) -and
        $postReconnectSessions.Count -eq 1 -and
        $postReconnectSessions[0].FullName -ne $preDisconnectSessionRoot) { break }
    Start-Sleep -Milliseconds 100
} while ([DateTime]::UtcNow -lt $deadline)
if ($remainingPartFiles.Count -ne 0 -or
    (Test-Path -LiteralPath $preDisconnectSessionRoot) -or
    $postReconnectSessions.Count -ne 1 -or
    $postReconnectSessions[0].FullName -eq $preDisconnectSessionRoot) {
    throw 'The interrupted DVC transfer did not produce one clean, distinct reconnect session spool.'
}
$preSessionNames = @($preDisconnectSessions.Name)
$postSessionNames = @($postReconnectSessions.Name)
$removedSessions = @($preSessionNames | Where-Object { $_ -notin $postSessionNames })
$addedSessions = @($postSessionNames | Where-Object { $_ -notin $preSessionNames })
if ($removedSessions.Count -ne 1 -or $addedSessions.Count -ne 1) {
    throw 'The transfer session set difference was not exactly one removed and one added session.'
}
Add-RuntimeNetworkSnapshot -Stage 'after-rdp-reconnect-before-new-transfer'
```

Finally repeat an exact small `write/stat/read` under a new filename:

```text
jts_windows_files {"targetId":"<targetId>","sessionId":"<new-sessionId>","operation":"write","rootId":"documents","path":"JTS-Evidence\\<RUN_ID>\\runtime-mcp\\files\\reconnect-inline.txt","contentBase64":"<inlineContentBase64>","overwrite":false}
jts_windows_files {"targetId":"<targetId>","sessionId":"<new-sessionId>","operation":"stat","rootId":"documents","path":"JTS-Evidence\\<RUN_ID>\\runtime-mcp\\files\\reconnect-inline.txt"}
jts_windows_files {"targetId":"<targetId>","sessionId":"<new-sessionId>","operation":"read","rootId":"documents","path":"JTS-Evidence\\<RUN_ID>\\runtime-mcp\\files\\reconnect-inline.txt"}
```

Require every response to contain `transportProof.channel=companion-dvc`, decode
the read response, and compare it byte-for-byte with `$inlineBytes`. Then verify
the same bytes independently on Windows and write the final report:

```powershell
$reconnectPath = Join-Path $filesRoot 'reconnect-inline.txt'
$reconnectLength = (Get-Item -LiteralPath $reconnectPath -ErrorAction Stop).Length
$reconnectSha256 = (Get-FileHash -Algorithm SHA256 `
    -LiteralPath $reconnectPath -ErrorAction Stop).Hash.ToLowerInvariant()
if ($reconnectLength -ne $inlineBytes.Length -or
    $reconnectSha256 -ne (Get-ByteArraySha256 -Bytes $inlineBytes)) {
    throw 'Fresh reconnect file I/O did not match the independent Windows hash.'
}
Add-RuntimeNetworkSnapshot -Stage 'after-fresh-reconnect-file-io'
$runtimeReport = [ordered]@{
    completedAtUtc = [DateTime]::UtcNow.ToString('o')
    fixture = $fixture
    outsideSentinelSha256After = $actualSentinelSha256
    disconnectCleanup = [ordered]@{
        observedPartFile = $disconnectObservationRecord
        oldSessionRoot = $preDisconnectSessionRoot
        newSessionRoot = $postReconnectSessions[0].FullName
        removedSessions = $removedSessions
        addedSessions = $addedSessions
        remainingPartFileCount = $remainingPartFiles.Count
    }
    reconnectFile = [ordered]@{
        path = $reconnectPath
        length = $reconnectLength
        sha256 = $reconnectSha256
    }
    networkSnapshots = $runtimeNetworkSnapshots.ToArray()
}
$runtimeReport | ConvertTo-Json -Depth 10 |
    Set-Content -LiteralPath "$runtimeRoot\runtime-mcp-postflight.json" -Encoding UTF8
```

Close the new desktop session cleanly only after this postflight report exists.
This proves the reconnect did not reuse stale transfer or authorization state.

Expected proof is: TLS/NLA desktop connected, `companionStatus` paired/ready,
one real PNG observation, `JTS_COMPANION_E2E_OK`, the complete positive and
negative file matrix, unchanged outside sentinel, old spool removal, successful
fresh-session file I/O, and zero staged Companion TCP/UDP endpoints.

## 9. Repeat artifact and runtime checks with the production candidate

The diagnostic key and `AUTHORIZED-LAB-ONLY` / `UNSIGNED-DEVELOPMENT` artifacts
cannot ship. Publish on Windows x64 with the designated external project release
key using `build-current-user-setup.ps1 -ReleasePrivateKeyPath <protected PEM>`.
Record the exact candidate hash, authenticated release manifest/public-key
fingerprint, payload hashes and source tuple before transferring the package.
On both Windows versions, repeat installation, DVC/pairing, actual UAC and
negative tamper/peer checks against these exact production bytes, including the
installed manifest. No private key enters QA output or the Mac bundle. This is
required even when Authenticode is not selected.

### Optional additional Authenticode profile

Only if the owner additionally elects Authenticode, the following certificate
and timestamp evidence applies. It is not a default no-certificate blocker. On both
the Windows 10 x64 and Windows 11 x64 clean machines, install the exact
production-signed candidate and capture `Get-JTSAuthenticodeEvidence` plus
`Invoke-JTSSignToolEvidence -RequireSuccess` for these four roles:

```text
production-candidate-setup
production-installed-agent
production-installed-uac-broker
production-installed-setup
```

Run the automated assertion after constructing `$productionFiles` with those
exact roles and exact candidate/installed paths:

```powershell
$releaseManifest = '<absolute path to the immutable production release manifest>'
$expectedReleaseManifestSha256 = '<64-hex digest from the external release record>'
$expectedSourceCommit = '<40-lowercase-hex commit from the external release record>'
$expectedPublisherThumbprint = '<40-hex publisher thumbprint from the external release record>'
$productionAuthenticodeEvidence = @($productionFiles | ForEach-Object {
    Get-JTSAuthenticodeEvidence -Role $_.role -Path $_.path
})
$productionSignToolEvidence = @(Invoke-JTSSignToolEvidence `
    -Files $productionFiles `
    -OutputDirectory "$evidence\production-signature-evidence" `
    -RequireSuccess)
$productionAssertion = Assert-JTSProductionAuthenticodeEvidence `
    -AuthenticodeEvidence $productionAuthenticodeEvidence `
    -SignToolEvidence $productionSignToolEvidence `
    -ReleaseManifestPath $releaseManifest `
    -ExpectedReleaseManifestSha256 $expectedReleaseManifestSha256 `
    -ExpectedSourceCommit $expectedSourceCommit `
    -ExpectedPublisherThumbprint $expectedPublisherThumbprint `
    -RunId $runId
$productionAssertion | ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath "$evidence\production-signature-assertion.json" -Encoding UTF8
```

The release manifest is prepared by the production signing/release system, not
derived ad hoc on either QA machine. Its externally pre-registered SHA-256 must
cover this exact schema and exact four-role hash set:

```json
{
  "schema": "jts-windows-companion-production-signing-v1",
  "sourceCommit": "<40-lowercase-hex>",
  "publisherThumbprint": "<40-uppercase-hex>",
  "files": [
    {"role":"production-candidate-setup","fileName":"<candidate name>.exe","sha256":"<64-lowercase-hex>"},
    {"role":"production-installed-agent","fileName":"JTS.WindowsCompanion.Agent.exe","sha256":"<64-lowercase-hex>"},
    {"role":"production-installed-uac-broker","fileName":"JTS.WindowsCompanion.UacBroker.exe","sha256":"<64-lowercase-hex>"},
    {"role":"production-installed-setup","fileName":"JTS.WindowsCompanion.Setup.exe","sha256":"<64-lowercase-hex>"}
  ]
}
```

Require every `Get-AuthenticodeSignature` result to be `Valid`; require one
identical signer thumbprint matching the pre-registered production publisher
across candidate, Agent, Broker, and installed Setup; require every role SHA-256
and filename to match the pre-registered release manifest; require
`hasTimestamp=true` and a non-null
`timeStamperCertificate` for all four; and require `signtool verify /pa /all /v`
to exit zero for each file through the identity-checked Microsoft Windows Kits
tool. Bind every record to the exact file SHA-256, source commit, OS
version/build, run ID, and production candidate manifest; the automated
assertion records the live Windows identity alongside those bindings. A lab
self-signed certificate, missing Windows SDK, missing timestamp, mixed signer,
or evidence from only one Windows version is incomplete.

No final production Companion or complete two-platform evidence set is claimed
by this source change. Absence of a commercial certificate does not block the
default manifest-verified distribution profile.

Store Mac-side results under the `MAC_RESULT_ROOT` printed by step 1 (or the
explicit `JTS_MAC_RESULT_ROOT` override):

```text
<MAC_RESULT_ROOT>/
```

Keep the pairing screenshot free of passwords and private file contents. Remove
the junction with `(Get-Item -LiteralPath $junctionPath -Force).Delete()` after
evidence capture; never recursively delete its target through the junction. The
authorized-lab results close engineering/runtime gates only; a production
release still requires the designated project-key manifest, exact candidate
provenance and final Windows 10/11 runtime acceptance. Authenticode/timestamp
evidence is additional only when that optional profile is selected.
