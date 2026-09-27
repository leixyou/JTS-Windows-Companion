[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $WorkingDirectory,
    [Parameter(Mandatory)] [string] $OutputRoot,
    [ValidateRange(3000, 30000)] [int] $ExpiryMilliseconds = 5000,
    # Historical parameters are rejected, never silently reused for QA trust.
    [string] $BrokerExecutable,
    [string] $CertificateThumbprint,
    [string] $TimestampUrl
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The historical script name is retained. "signed" now means a project P-256
# manifest signed with a fresh diagnostic key, NOT production Authenticode.
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne
        [Runtime.InteropServices.Architecture]::X64) {
    throw 'The manifest-verified elevation protocol QA must run on Windows 10/11 x64.'
}
if (-not [string]::IsNullOrWhiteSpace($BrokerExecutable) -or
    -not [string]::IsNullOrWhiteSpace($CertificateThumbprint) -or
    -not [string]::IsNullOrWhiteSpace($TimestampUrl)) {
    throw 'External brokers and signing certificates are no longer accepted. This QA builds its own nonproduction runner and Broker with a fresh diagnostic key.'
}

function Assert-NoReparsePath {
    param([Parameter(Mandatory)] [string] $Path)
    $current = [IO.Path]::GetFullPath($Path)
    if ($current.StartsWith('\\')) { throw 'QA paths must be local, not UNC paths.' }
    while (-not [string]::IsNullOrEmpty($current)) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "A QA path or ancestor is a reparse point: $current"
            }
        }
        $current = [IO.Path]::GetDirectoryName($current)
    }
}

function Get-LockedFileEvidence {
    param([Parameter(Mandatory)] [string] $Path)
    $fullPath = [IO.Path]::GetFullPath($Path)
    Assert-NoReparsePath -Path $fullPath
    $stream = [IO.File]::Open($fullPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        Assert-NoReparsePath -Path $fullPath
        if ($stream.Length -le 0) { throw 'A QA evidence artifact is empty.' }
        $algorithm = [Security.Cryptography.SHA256]::Create()
        try { $digest = $algorithm.ComputeHash($stream) } finally { $algorithm.Dispose() }
        return [ordered]@{
            Path = $fullPath
            LengthBytes = $stream.Length
            Sha256 = [BitConverter]::ToString($digest).Replace('-', '').ToLowerInvariant()
        }
    } finally { $stream.Dispose() }
}

function Assert-SameFileEvidence {
    param([Parameter(Mandatory)] $Expected, [Parameter(Mandatory)] $Actual)
    if (($Actual.LengthBytes -isnot [int] -and $Actual.LengthBytes -isnot [long]) -or
        [string]$Actual.Path -ine [string]$Expected.Path -or
        [int64]$Actual.LengthBytes -ne [int64]$Expected.LengthBytes -or
        [string]$Actual.Sha256 -cne [string]$Expected.Sha256) {
        throw 'A QA artifact changed after its pre-run hash was recorded.'
    }
}

function Publish-DiagnosticExecutable {
    param([Parameter(Mandatory)] [string] $Project, [Parameter(Mandatory)] [string] $Destination)
    & dotnet publish $Project --configuration Release --runtime win-x64 `
        --self-contained true --output $Destination `
        -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:PublishTrimmed=false -p:DebugType=None -p:DebugSymbols=false `
        -p:ContinuousIntegrationBuild=true "-p:CompanionReleasePublicKeyPath=$publicKeyPath" --nologo
    if ($LASTEXITCODE -ne 0) { throw 'Publishing the diagnostic elevation executable failed.' }
}

$companionRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$WorkingDirectory = [IO.Path]::GetFullPath($WorkingDirectory)
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
Assert-NoReparsePath -Path $WorkingDirectory
Assert-NoReparsePath -Path $OutputRoot
if (-not (Test-Path -LiteralPath $WorkingDirectory -PathType Container)) {
    throw 'The bounded QA working directory is unavailable.'
}
if (Test-Path -LiteralPath $OutputRoot) {
    throw 'Use a new OutputRoot for each diagnostic elevation run; existing evidence is never overwritten.'
}
New-Item -ItemType Directory -Path $OutputRoot | Out-Null
$publishRoot = Join-Path $OutputRoot 'diagnostic-runtime'
$runnerOutput = Join-Path $OutputRoot 'runner-publish'
$brokerOutput = Join-Path $OutputRoot 'broker-publish'
$toolOutput = Join-Path $OutputRoot 'manifest-tool'
$evidenceDirectory = Join-Path $OutputRoot 'evidence'
New-Item -ItemType Directory -Path $publishRoot, $evidenceDirectory | Out-Null
$runnerProject = Join-Path $companionRoot 'tools\JTS.WindowsCompanion.ElevationQaRunner\JTS.WindowsCompanion.ElevationQaRunner.csproj'
$brokerProject = Join-Path $companionRoot 'src\JTS.WindowsCompanion.UacBroker\JTS.WindowsCompanion.UacBroker.csproj'
$toolProject = Join-Path $companionRoot 'tools\JTS.WindowsCompanion.ReleaseManifestTool\JTS.WindowsCompanion.ReleaseManifestTool.csproj'
$manifestTool = Join-Path $toolOutput 'JTS.WindowsCompanion.ReleaseManifestTool.dll'
$privateKeyPath = Join-Path $OutputRoot 'diagnostic-private-key.pem'
$publicKeyPath = Join-Path $OutputRoot 'diagnostic-public-key.pem'
$releaseId = 'qa-elevation-' + [Guid]::NewGuid().ToString('N')
$runner = Join-Path $publishRoot 'JTS.WindowsCompanion.Agent.exe'
$broker = Join-Path $publishRoot 'JTS.WindowsCompanion.UacBroker.exe'
$releaseManifestPath = Join-Path $publishRoot 'JTS.WindowsCompanion.release.json'

try {
    & dotnet publish $toolProject --configuration Release --output $toolOutput --nologo
    if ($LASTEXITCODE -ne 0) { throw 'Publishing the release manifest tool failed.' }
    # RestrictedKeyFile applies an owner-only DACL before any private bytes exist.
    # No key path is accepted from parameters or the production-key environment.
    & dotnet $manifestTool keygen --private-key $privateKeyPath
    if ($LASTEXITCODE -ne 0) { throw 'Generating the diagnostic-only key failed.' }
    & dotnet $manifestTool public-key --private-key $privateKeyPath --output $publicKeyPath
    if ($LASTEXITCODE -ne 0) { throw 'Exporting the diagnostic public key failed.' }
    Publish-DiagnosticExecutable -Project $runnerProject -Destination $runnerOutput
    Publish-DiagnosticExecutable -Project $brokerProject -Destination $brokerOutput
    Copy-Item -LiteralPath (Join-Path $runnerOutput 'JTS.WindowsCompanion.Agent.exe') -Destination $runner
    Copy-Item -LiteralPath (Join-Path $brokerOutput 'JTS.WindowsCompanion.UacBroker.exe') -Destination $broker
    & dotnet $manifestTool sign --private-key $privateKeyPath --release-id $releaseId `
        --output $releaseManifestPath --file $runner --file $broker
    if ($LASTEXITCODE -ne 0) { throw 'Signing the diagnostic release manifest failed.' }
} finally {
    # Remove only this invocation's fresh diagnostic private key, even on failure.
    if (Test-Path -LiteralPath $privateKeyPath) {
        Remove-Item -LiteralPath $privateKeyPath -Force -ErrorAction Stop
    }
}
if (Test-Path -LiteralPath $privateKeyPath) { throw 'The diagnostic private key was not removed.' }

$before = [ordered]@{
    runner = Get-LockedFileEvidence -Path $runner
    broker = Get-LockedFileEvidence -Path $broker
    manifest = Get-LockedFileEvidence -Path $releaseManifestPath
    publicKey = Get-LockedFileEvidence -Path $publicKeyPath
}
$envelope = Get-Content -LiteralPath $releaseManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
$payloadBytes = [Convert]::FromBase64String([string]$envelope.payload)
$algorithm = [Security.Cryptography.SHA256]::Create()
try { $payloadDigest = $algorithm.ComputeHash($payloadBytes) } finally { $algorithm.Dispose() }
$manifestPayloadSha256 = [BitConverter]::ToString($payloadDigest).Replace('-', '').ToLowerInvariant()

& $runner --broker $broker --working-directory $WorkingDirectory `
    --evidence-directory $evidenceDirectory --expiry-ms $ExpiryMilliseconds
if ($LASTEXITCODE -ne 0) { throw 'The manifest-verified elevation protocol QA runner failed.' }

$evidencePath = Join-Path $evidenceDirectory 'elevation-protocol-qa.json'
Assert-NoReparsePath -Path $evidencePath
$evidence = Get-Content -LiteralPath $evidencePath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
foreach ($number in @($evidence.schemaVersion, $evidence.brokerVerificationCount,
    $evidence.exactPayload.brokerProcessId, $evidence.expiry.brokerProcessId,
    $evidence.exactPayload.executionCount, $evidence.expiry.durationMilliseconds,
    $evidence.exactPayload.brokerExitCode, $evidence.expiry.brokerExitCode)) {
    if ($number -isnot [int] -and $number -isnot [long]) {
        throw 'Elevation schema/count/PID/duration/exit fields must be JSON integers, never null or coerced values.'
    }
}
if ([int]$evidence.schemaVersion -ne 3 -or
    [string]$evidence.runId -notmatch '\A[0-9a-f]{32}\z' -or
    [string]$evidence.trust.mechanism -cne 'project-p256-release-manifest' -or
    [string]$evidence.trust.releaseId -cne $releaseId -or
    [string]$evidence.trust.manifestPayloadSha256 -cne $manifestPayloadSha256 -or
    $evidence.trust.diagnosticOnly -isnot [bool] -or $evidence.trust.diagnosticOnly -ne $true -or
    [int]$evidence.brokerVerificationCount -ne 2 -or
    [int]$evidence.exactPayload.brokerProcessId -le 0 -or
    [int]$evidence.expiry.brokerProcessId -le 0 -or
    [string]$evidence.exactPayload.leaseId -notmatch '\A[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\z' -or
    [string]$evidence.expiry.leaseId -notmatch '\A[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\z' -or
    [string]$evidence.exactPayload.leaseId -ceq [string]$evidence.expiry.leaseId -or
    [int]$evidence.exactPayload.executionCount -ne 1 -or
    $evidence.exactPayload.markerObserved -isnot [bool] -or
    $evidence.exactPayload.markerObserved -ne $true -or
    [string]$evidence.exactPayload.markerValue -cne '1' -or
    $evidence.exactPayload.brokerManifestVerifiedWhileLocked -isnot [bool] -or
    $evidence.exactPayload.brokerManifestVerifiedWhileLocked -ne $true -or
    $evidence.exactPayload.brokerExitedNaturally -isnot [bool] -or
    $evidence.exactPayload.brokerExitedNaturally -ne $true -or
    [int]$evidence.exactPayload.brokerExitCode -ne 0 -or
    @($evidence.tamperChecks).Count -ne 4 -or
    @($evidence.tamperChecks.field | Select-Object -Unique).Count -ne 4 -or
    @($evidence.tamperChecks | Where-Object {
        $_.field -notin @('script', 'path', 'scope', 'timeout') -or
        $_.errorCode -ne 'NOT_AUTHORIZED' -or
        $_.markerUnchanged -isnot [bool] -or $_.markerUnchanged -ne $true
    }).Count -ne 0 -or
    [int]$evidence.expiry.durationMilliseconds -ne $ExpiryMilliseconds -or
    $evidence.expiry.errorCode -ne 'LEASE_EXPIRED' -or
    $evidence.expiry.startedMarkerObserved -isnot [bool] -or
    $evidence.expiry.startedMarkerObserved -ne $true -or
    $evidence.expiry.completedMarkerAbsent -isnot [bool] -or
    $evidence.expiry.completedMarkerAbsent -ne $true -or
    $evidence.expiry.brokerManifestVerifiedWhileLocked -isnot [bool] -or
    $evidence.expiry.brokerManifestVerifiedWhileLocked -ne $true -or
    $evidence.expiry.brokerExitedNaturally -isnot [bool] -or
    $evidence.expiry.brokerExitedNaturally -ne $true -or
    [int]$evidence.expiry.brokerExitCode -ne 0) {
    throw 'The real diagnostic elevation protocol evidence is incomplete or malformed.'
}

$after = [ordered]@{
    runner = Get-LockedFileEvidence -Path $runner
    broker = Get-LockedFileEvidence -Path $broker
    manifest = Get-LockedFileEvidence -Path $releaseManifestPath
    publicKey = Get-LockedFileEvidence -Path $publicKeyPath
}
foreach ($role in @('runner', 'broker', 'manifest', 'publicKey')) {
    Assert-SameFileEvidence -Expected $before[$role] -Actual $after[$role]
}
Assert-SameFileEvidence -Expected $before.runner -Actual $evidence.runner
Assert-SameFileEvidence -Expected $before.broker -Actual $evidence.broker
$evidence | Add-Member -MemberType NoteProperty -Name 'diagnosticBuild' -Value ([ordered]@{
    nonProduction = $true
    privateKeyRemovedBeforeRun = $true
    before = $before
    after = $after
})
$serializedEvidence = $evidence | ConvertTo-Json -Depth 12
Assert-NoReparsePath -Path $evidencePath
$evidenceLock = [IO.File]::Open($evidencePath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
try {
    Assert-NoReparsePath -Path $evidencePath
    $evidenceBytes = [Text.UTF8Encoding]::new($false).GetBytes($serializedEvidence)
    $evidenceLock.SetLength(0)
    $evidenceLock.Write($evidenceBytes, 0, $evidenceBytes.Length)
    $evidenceLock.Flush($true)
} finally { $evidenceLock.Dispose() }
Write-Host "Diagnostic elevation protocol QA passed (NOT FOR DISTRIBUTION): $evidencePath"
