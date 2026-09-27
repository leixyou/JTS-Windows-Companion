[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $RequestPath,
    [Parameter(Mandatory = $true)][string] $RequestSha256,
    [Parameter(Mandatory = $true)][string] $RelayOrigin,
    [string] $ExportPath = (Join-Path $PSScriptRoot 'windows-enrollment.json'),
    [switch] $RelayOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-JTSConnectionPackagePlan {
    param([string] $PackageRoot, [object] $Manifest, [switch] $RelayOnly)
    if (-not $RelayOnly) {
        [pscustomobject]@{ Role = 'current-user'; Path = (Join-Path (Join-Path $PackageRoot 'current-user') 'JTS.WindowsCompanion.Setup.exe'); Hash = $Manifest.currentUserSha256 }
    }
    [pscustomobject]@{ Role = 'independent'; Path = (Join-Path (Join-Path $PackageRoot 'independent') 'JTS.WindowsCompanion.Setup.exe'); Hash = $Manifest.independentSha256 }
}
function Assert-JTSConnectionIdentity {
    param([bool] $IsSystem, [bool] $IsAdministrator, [switch] $RelayOnly)
    if ($IsSystem) { throw 'Start from an interactive user session, not SYSTEM.' }
    if ($IsAdministrator -and -not $RelayOnly) {
        throw 'Current-user setup must start without elevation. Use -RelayOnly for an elevated console relay bootstrap.'
    }
}
$nativeArchitecture = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITEW6432')
if ([string]::IsNullOrEmpty($nativeArchitecture)) { $nativeArchitecture = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE') }
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or $nativeArchitecture -ine 'AMD64') {
    throw 'Windows x64 is required.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    Assert-JTSConnectionIdentity -IsSystem $identity.IsSystem -IsAdministrator ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) -RelayOnly:$RelayOnly
} finally { $identity.Dispose() }

$manifestPath = Join-Path $PSScriptRoot 'connection-package.json'
$manifest = [IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
if ($manifest.schemaVersion -ne 1 -or $manifest.kind -cne 'authorized-lab-cross-build') { throw 'Package manifest rejected.' }
$plan = @(Get-JTSConnectionPackagePlan -PackageRoot $PSScriptRoot -Manifest $manifest -RelayOnly:$RelayOnly)
foreach ($item in $plan) {
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

# Default installs the interactive Agent first and must run inside a connected RDP session.
# RelayOnly bootstraps an outbound route from the local console without invoking the DVC readiness gate.
foreach ($item in $plan) {
    if ($item.Role -ceq 'current-user') {
        $current = Start-Process -FilePath $item.Path -ArgumentList '--install --quiet' -PassThru
        if (-not $current.WaitForExit(120000)) { throw 'Current-user setup may still be running. Preserve state and inspect before retrying.' }
        $current.Refresh()
        if ($current.ExitCode -ne 0) { throw ('Current-user setup failed with exit code {0}. For first-time console bootstrap use -RelayOnly, then install the Agent inside the connected RDP session.' -f $current.ExitCode) }
    } else {
        $arguments = '--relay "{0}" --delegated-enrollment "{1}" --sha256 {2} --export "{3}"' -f $RelayOrigin, $request, $RequestSha256, $export
        $service = Start-Process -FilePath $item.Path -Verb RunAs -ArgumentList $arguments -PassThru
        if (-not $service.WaitForExit(180000)) { throw 'Service setup may still be running. Preserve state and inspect before retrying.' }
        $service.Refresh()
        if ($service.ExitCode -ne 0) { throw ('Service setup failed with exit code {0}; no automatic rollback or retry was attempted.' -f $service.ExitCode) }
    }
}
if (-not (Test-Path -LiteralPath $export -PathType Leaf)) { throw 'Setup did not produce its public enrollment.' }
$size = (Get-Item -LiteralPath $export).Length
if ($size -lt 1 -or $size -gt 16384) { throw 'Public enrollment size rejected.' }
Write-Output 'installedAwaitingRelayAdmission'
Write-Output ('Public enrollment: {0}' -f $export)
if ($RelayOnly) {
    Write-Output 'Relay endpoint installed. After relay admission and RDP connection, run current-user\JTS.WindowsCompanion.Setup.exe inside that RDP session to add semantic UIA.'
} else {
    Write-Output 'Current-user Agent installed. New-device semantic UIA authorization is completed through its separate DVC identity handshake.'
}
