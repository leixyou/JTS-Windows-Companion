[CmdletBinding()]
param(
    [string] $OutputRoot,
    [switch] $RequireSignToolEvidence,
    [switch] $CaptureAuthenticodeDiagnostics,
    [switch] $RequireInteractiveUIA,
    [switch] $RequireInteractiveConsent,
    [switch] $RequireInteractiveUAC,
    [string] $ElevationBrokerExecutable,
    [string] $ElevationWorkingDirectory,
    [string] $ElevationCertificateThumbprint,
    [string] $ElevationTimestampUrl,
    [ValidateRange(3000, 30000)] [int] $ElevationExpiryMilliseconds = 5000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'The authorized Windows Companion lab run must execute on Windows.'
}
if ($RequireSignToolEvidence) {
    throw 'Mandatory Authenticode evidence is no longer part of this diagnostic harness. Use CaptureAuthenticodeDiagnostics for optional metadata.'
}
if (-not [string]::IsNullOrWhiteSpace($ElevationBrokerExecutable) -or
    -not [string]::IsNullOrWhiteSpace($ElevationCertificateThumbprint) -or
    -not [string]::IsNullOrWhiteSpace($ElevationTimestampUrl)) {
    throw 'Historical elevation broker/certificate arguments are no longer accepted; the UAC harness builds isolated diagnostic-key artifacts.'
}
if ($RequireInteractiveUAC -and
    [string]::IsNullOrWhiteSpace($ElevationWorkingDirectory)) {
    throw 'RequireInteractiveUAC also requires ElevationWorkingDirectory.'
}

$companionRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$testProjectRelativePath = 'tests/JTS.WindowsCompanion.Tests/JTS.WindowsCompanion.Tests.csproj'
$testProjectPath = Join-Path $companionRoot `
    'tests\JTS.WindowsCompanion.Tests\JTS.WindowsCompanion.Tests.csproj'
$testInventoryPath = Join-Path $companionRoot `
    'tests\JTS.WindowsCompanion.Tests\release-test-inventory.json'
. (Join-Path $PSScriptRoot 'windows-companion-trx-evidence.ps1')
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
    $OutputRoot = Join-Path $companionRoot "artifacts\authorized-lab-run\$stamp"
}
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
$candidateRoot = Join-Path $OutputRoot 'candidate'
$evidenceRoot = Join-Path $OutputRoot 'evidence'
New-Item -ItemType Directory -Path $candidateRoot, $evidenceRoot -Force | Out-Null
$transcriptPath = Join-Path $evidenceRoot 'authorized-lab-transcript.txt'
$testResultsRoot = Join-Path $evidenceRoot 'test-results'
$trxPath = Join-Path $testResultsRoot 'windows-companion-release.trx'
New-Item -ItemType Directory -Path $testResultsRoot -Force | Out-Null

function Assert-DiagnosticLocalPath {
    param([Parameter(Mandatory)] [string] $Path)
    $current = [IO.Path]::GetFullPath($Path)
    if ($current.StartsWith('\\')) { throw 'Diagnostic evidence must use local paths.' }
    while (-not [string]::IsNullOrEmpty($current)) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "A diagnostic evidence path or ancestor is a reparse point: $current"
            }
        }
        $current = [IO.Path]::GetDirectoryName($current)
    }
}

function Get-DiagnosticFileEvidence {
    param([Parameter(Mandatory)] [string] $Path)
    $fullPath = [IO.Path]::GetFullPath($Path)
    Assert-DiagnosticLocalPath -Path $fullPath
    $stream = [IO.File]::Open($fullPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        Assert-DiagnosticLocalPath -Path $fullPath
        if ($stream.Length -le 0) { throw 'A diagnostic artifact is empty.' }
        $algorithm = [Security.Cryptography.SHA256]::Create()
        try { $digest = $algorithm.ComputeHash($stream) } finally { $algorithm.Dispose() }
        return [ordered]@{
            Path = $fullPath
            LengthBytes = $stream.Length
            Sha256 = [BitConverter]::ToString($digest).Replace('-', '').ToLowerInvariant()
        }
    } finally { $stream.Dispose() }
}

function Assert-DiagnosticFileEvidence {
    param([Parameter(Mandatory)] $Expected, [Parameter(Mandatory)] $Actual)
    if (($Actual.LengthBytes -isnot [int] -and $Actual.LengthBytes -isnot [long]) -or
        [string]$Actual.Path -ine [string]$Expected.Path -or
        [int64]$Actual.LengthBytes -ne [int64]$Expected.LengthBytes -or
        [string]$Actual.Sha256 -cne [string]$Expected.Sha256) {
        throw 'Diagnostic elevation evidence is detached from the exact local artifact.'
    }
}

function Get-ValidatedElevationProtocolEvidence {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $DiagnosticOutputRoot,
        [Parameter(Mandatory)] [int] $ExpiryMilliseconds
    )

    Assert-DiagnosticLocalPath -Path $Path
    $evidence = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 |
        ConvertFrom-Json -ErrorAction Stop
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
        [string]$evidence.trust.releaseId -notmatch '\Aqa-elevation-[0-9a-f]{32}\z' -or
        [string]$evidence.trust.manifestPayloadSha256 -notmatch '\A[0-9a-f]{64}\z' -or
        $evidence.trust.diagnosticOnly -isnot [bool] -or $evidence.trust.diagnosticOnly -ne $true -or
        $evidence.diagnosticBuild.nonProduction -isnot [bool] -or $evidence.diagnosticBuild.nonProduction -ne $true -or
        $evidence.diagnosticBuild.privateKeyRemovedBeforeRun -isnot [bool] -or $evidence.diagnosticBuild.privateKeyRemovedBeforeRun -ne $true -or
        [int]$evidence.brokerVerificationCount -ne 2 -or
        [int]$evidence.exactPayload.brokerProcessId -le 0 -or
        [int]$evidence.expiry.brokerProcessId -le 0 -or
        [string]$evidence.exactPayload.leaseId -notmatch
            '\A[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\z' -or
        [string]$evidence.expiry.leaseId -notmatch
            '\A[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\z' -or
        [string]$evidence.exactPayload.leaseId -ceq
            [string]$evidence.expiry.leaseId -or
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
            $_.markerUnchanged -isnot [bool] -or
            $_.markerUnchanged -ne $true
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

    # Derive paths from this invocation, never from untrusted evidence fields.
    $runtimeRoot = Join-Path $DiagnosticOutputRoot 'diagnostic-runtime'
    $manifestPath = Join-Path $runtimeRoot 'JTS.WindowsCompanion.release.json'
    $expectedPaths = [ordered]@{
        runner = Join-Path $runtimeRoot 'JTS.WindowsCompanion.Agent.exe'
        broker = Join-Path $runtimeRoot 'JTS.WindowsCompanion.UacBroker.exe'
        manifest = $manifestPath
        publicKey = Join-Path $DiagnosticOutputRoot 'diagnostic-public-key.pem'
    }
    foreach ($role in @('runner', 'broker', 'manifest', 'publicKey')) {
        $live = Get-DiagnosticFileEvidence -Path $expectedPaths[$role]
        Assert-DiagnosticFileEvidence -Expected $live -Actual $evidence.diagnosticBuild.before.$role
        Assert-DiagnosticFileEvidence -Expected $live -Actual $evidence.diagnosticBuild.after.$role
        if ($role -in @('runner', 'broker')) {
            Assert-DiagnosticFileEvidence -Expected $live -Actual $evidence.$role
        }
    }
    if (Test-Path -LiteralPath (Join-Path $DiagnosticOutputRoot 'diagnostic-private-key.pem')) {
        throw 'The diagnostic private key was retained; this is not accepted QA evidence.'
    }
    $envelope = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    $payloadBytes = [Convert]::FromBase64String([string]$envelope.payload)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { $digest = $algorithm.ComputeHash($payloadBytes) } finally { $algorithm.Dispose() }
    $payloadSha256 = [BitConverter]::ToString($digest).Replace('-', '').ToLowerInvariant()
    $payload = [Text.Encoding]::UTF8.GetString($payloadBytes) | ConvertFrom-Json -ErrorAction Stop
    if ([string]$evidence.trust.manifestPayloadSha256 -cne $payloadSha256 -or
        [string]$evidence.trust.releaseId -cne [string]$payload.releaseId) {
        throw 'The diagnostic evidence does not identify the exact signed manifest payload.'
    }

    return $evidence
}

Start-Transcript -LiteralPath $transcriptPath -Force | Out-Null
try {
    Push-Location $companionRoot
    try {
        & dotnet --info
        if ($LASTEXITCODE -ne 0) { throw 'The .NET SDK is unavailable.' }
        & dotnet restore 'JTS.WindowsCompanion.sln' --nologo
        if ($LASTEXITCODE -ne 0) { throw 'dotnet restore failed.' }
        & dotnet build 'JTS.WindowsCompanion.sln' `
            --configuration Release `
            --no-restore `
            --nologo
        if ($LASTEXITCODE -ne 0) { throw 'dotnet build failed.' }
        Remove-Item -LiteralPath $trxPath -Force -ErrorAction SilentlyContinue
        $previousUiAutomationFlag = $env:JTS_RUN_INTERACTIVE_UIA_TESTS
        $previousUiAutomationFixture = $env:JTS_UIA_FIXTURE_EXECUTABLE
        $previousConsentFlag = $env:JTS_RUN_INTERACTIVE_CONSENT_TESTS
        try {
            if ($RequireInteractiveUIA) {
                $env:JTS_RUN_INTERACTIVE_UIA_TESTS = '1'
                $env:JTS_UIA_FIXTURE_EXECUTABLE = Join-Path $companionRoot `
                    'tools\JTS.WindowsCompanion.UiAutomationFixture\bin\Release\net8.0-windows10.0.19041.0\JTS.WindowsCompanion.UiAutomationFixture.exe'
                if (-not (Test-Path -LiteralPath $env:JTS_UIA_FIXTURE_EXECUTABLE -PathType Leaf)) {
                    throw 'The independently built UI Automation fixture executable is unavailable.'
                }
            }
            if ($RequireInteractiveConsent) {
                $env:JTS_RUN_INTERACTIVE_CONSENT_TESTS = '1'
            }
            & dotnet test $testProjectPath `
                --configuration Release `
                --no-build `
                --no-restore `
                --nologo `
                --logger 'console;verbosity=minimal' `
                --logger 'trx;LogFileName=windows-companion-release.trx' `
                --results-directory $testResultsRoot
            if ($LASTEXITCODE -ne 0) {
                throw 'The Windows Companion Release suite failed.'
            }
        } finally {
            $env:JTS_RUN_INTERACTIVE_UIA_TESTS = $previousUiAutomationFlag
            $env:JTS_UIA_FIXTURE_EXECUTABLE = $previousUiAutomationFixture
            $env:JTS_RUN_INTERACTIVE_CONSENT_TESTS = $previousConsentFlag
        }
        $testEvidence = Get-JTSTrxEvidence `
            -Path $trxPath `
            -InventoryPath $testInventoryPath `
            -ExpectedProjectPath $testProjectRelativePath `
            -RequireInteractiveUiAutomation:$RequireInteractiveUIA `
            -RequireInteractiveConsent:$RequireInteractiveConsent `
            -RequireWindowsIntegration

        $elevationProtocolEvidencePath = $null
        $elevationProtocolEvidence = $null
        if ($RequireInteractiveUAC) {
            $elevationOutputRoot = Join-Path $evidenceRoot 'signed-elevation-protocol'
            $elevationArguments = @{
                WorkingDirectory = $ElevationWorkingDirectory
                OutputRoot = $elevationOutputRoot
                ExpiryMilliseconds = $ElevationExpiryMilliseconds
            }
            & (Join-Path $PSScriptRoot 'run-signed-elevation-protocol-qa.ps1') `
                @elevationArguments
            $elevationProtocolEvidencePath = Join-Path $elevationOutputRoot `
                'evidence\elevation-protocol-qa.json'
            $elevationProtocolEvidence = Get-ValidatedElevationProtocolEvidence `
                -Path $elevationProtocolEvidencePath `
                -DiagnosticOutputRoot $elevationOutputRoot `
                -ExpiryMilliseconds $ElevationExpiryMilliseconds
        }

        & (Join-Path $PSScriptRoot 'build-authorized-lab-setup.ps1') `
            -OutputDirectory $candidateRoot
        $candidate = Join-Path $candidateRoot `
            'JTS-Windows-Companion-2.0.0-win-x64-AUTHORIZED-LAB-ONLY.exe'
        # Pin the just-completed local build before the tester launches any Setup.
        # The tester must not decide trust from an unpinned adjacent .sha256 file.
        $buildEvidencePath = Join-Path $candidateRoot 'build-evidence.json'
        $buildEvidenceSnapshot = Get-DiagnosticFileEvidence -Path $buildEvidencePath
        & (Join-Path $PSScriptRoot 'test-authorized-lab-setup.ps1') `
            -CandidatePath $candidate `
            -BuildEvidencePath $buildEvidencePath `
            -ExpectedBuildEvidenceSha256 $buildEvidenceSnapshot.Sha256 `
            -EvidenceDirectory $evidenceRoot `
            -CaptureAuthenticodeDiagnostics:$CaptureAuthenticodeDiagnostics

        $summary = [ordered]@{
            completedAtUtc = [DateTime]::UtcNow.ToString('o')
            warning = 'AUTHORIZED LAB ONLY - NOT FOR DISTRIBUTION OR RELEASE SIGNING EVIDENCE'
            computerName = $env:COMPUTERNAME
            authenticodeRequired = $false
            authenticodeDiagnosticsCaptured = $CaptureAuthenticodeDiagnostics.IsPresent
            interactiveUiAutomationRequired = $RequireInteractiveUIA.IsPresent
            interactiveConsentRequired = $RequireInteractiveConsent.IsPresent
            interactiveUacRequired = $RequireInteractiveUAC.IsPresent
            windowsIntegrationRequired = $true
            testEvidence = $testEvidence
            elevationProtocolEvidence = $elevationProtocolEvidencePath
            elevationProtocolRunId = if ($null -eq $elevationProtocolEvidence) {
                $null
            } else {
                [string]$elevationProtocolEvidence.runId
            }
            candidateManifest = $buildEvidencePath
            expectedBuildEvidenceSha256 = $buildEvidenceSnapshot.Sha256
            qaEvidence = Join-Path $evidenceRoot 'authorized-lab-setup-qa.json'
            evidenceIncludes = @(
                'candidate and installed-file SHA-256 bound to the pre-install local diagnostic build snapshot and exact project-signed manifest bytes'
                'optional Authenticode/signtool metadata is diagnostic only, never the runtime trust or a required Valid publisher result'
                'stage-bound exact-image process and bounded post-hash TCP/UDP endpoint stability window with terminal identity revalidation'
                'independent-process UI Automation bound to the launched child PID when required'
                'nonproduction diagnostic P-256 manifest UAC broker exact-payload, tamper, expiry, locked-image, before/after hashes, and natural-exit evidence when required'
            )
            transcript = $transcriptPath
        }
        $summary | ConvertTo-Json -Depth 4 | Set-Content `
            -LiteralPath (Join-Path $OutputRoot 'authorized-lab-run-summary.json') `
            -Encoding UTF8
        Write-Host "Authorized Windows Companion lab run passed: $OutputRoot"
    } finally {
        Pop-Location
    }
} finally {
    Stop-Transcript | Out-Null
}
