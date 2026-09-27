[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $RequestPath,
    [Parameter(Mandatory = $true)][string] $RequestSha256,
    [Parameter(Mandatory = $true)][string] $RelayOrigin,
    [string] $ExportPath = (Join-Path $PSScriptRoot 'windows-enrollment.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [Runtime.InteropServices.Architecture]::X64) {
    throw 'Windows x64 is required.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($identity.IsSystem -or $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Start from the intended logged-in user without elevation. Only the separate service installer requests UAC.'
    }
} finally { $identity.Dispose() }

$manifestPath = Join-Path $PSScriptRoot 'connection-package.json'
$manifest = [IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
if ($manifest.schemaVersion -ne 1 -or $manifest.kind -cne 'authorized-lab-cross-build') { throw 'Package manifest rejected.' }
$currentSetup = Join-Path $PSScriptRoot 'current-user\JTS.WindowsCompanion.Setup.exe'
$serviceSetup = Join-Path $PSScriptRoot 'independent\JTS.WindowsCompanion.Setup.exe'
foreach ($item in @(@{ Path = $currentSetup; Hash = $manifest.currentUserSha256 }, @{ Path = $serviceSetup; Hash = $manifest.independentSha256 })) {
    if ($item.Hash -cnotmatch '^[0-9a-f]{64}$' -or
        (Get-FileHash -LiteralPath $item.Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $item.Hash) {
        throw 'An installer does not match the pinned connection package.'
    }
}
$request = [IO.Path]::GetFullPath($RequestPath)
$export = [IO.Path]::GetFullPath($ExportPath)
if ($RequestSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    (Get-FileHash -LiteralPath $request -Algorithm SHA256).Hash.ToLowerInvariant() -cne $RequestSha256) {
    throw 'The public owner-delegation request hash does not match.'
}
if (Test-Path -LiteralPath $export) { throw 'The public enrollment export must be a new file.' }
foreach ($argument in @($request, $export, $RelayOrigin)) {
    if ($argument.Contains('"') -or $argument.Contains("`r") -or $argument.Contains("`n")) { throw 'Unsafe installer argument.' }
}

# Wait only for Setup, not its Agent descendant. Never terminate unknown/installed processes on timeout.
$current = Start-Process -FilePath $currentSetup -ArgumentList '--install --quiet' -PassThru
if (-not $current.WaitForExit(120000)) { throw 'Current-user setup may still be running. Preserve state and inspect before retrying.' }
if ($current.ExitCode -ne 0) { throw ('Current-user setup failed with exit code {0}.' -f $current.ExitCode) }

$arguments = '--relay "{0}" --delegated-enrollment "{1}" --sha256 {2} --export "{3}"' -f $RelayOrigin, $request, $RequestSha256, $export
$service = Start-Process -FilePath $serviceSetup -Verb RunAs -ArgumentList $arguments -PassThru
if (-not $service.WaitForExit(180000)) { throw 'Service setup may still be running. Preserve state and inspect before retrying.' }
if ($service.ExitCode -ne 0) { throw ('Service setup failed with exit code {0}; no automatic rollback or retry was attempted.' -f $service.ExitCode) }
if (-not (Test-Path -LiteralPath $export -PathType Leaf)) { throw 'Setup did not produce its public enrollment.' }
$size = (Get-Item -LiteralPath $export).Length
if ($size -lt 1 -or $size -gt 16384) { throw 'Public enrollment size rejected.' }
Write-Output 'installedAwaitingRelayAdmission'
Write-Output ('Public enrollment: {0}' -f $export)
Write-Output 'Current-user Agent installed. New-device semantic UIA authorization is completed through its separate DVC identity handshake.'
