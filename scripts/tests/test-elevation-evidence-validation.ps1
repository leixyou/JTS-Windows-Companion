[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptsRoot = Split-Path -Parent $PSScriptRoot
$parsed = @{}
foreach ($file in Get-ChildItem -LiteralPath $scriptsRoot -Filter '*.ps1') {
    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $file.FullName, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -ne 0) { throw ($parseErrors | Out-String) }
    $parsed[$file.Name] = $ast
}

# Exercise the actual pure schema guards, not a reimplementation of them.
# Never dot-source either Windows driver: its build/install/UAC code must not run.
function Get-SchemaGuard {
    param([Management.Automation.Language.ScriptBlockAst] $Ast)
    $typeChecks = @($Ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.ForEachStatementAst] -and
        $node.Extent.Text.StartsWith('foreach ($number in @($evidence.schemaVersion,')
    }, $true))
    $valueChecks = @($Ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.IfStatementAst] -and
        $node.Extent.Text.StartsWith('if ([int]$evidence.schemaVersion -ne 3 -or')
    }, $true))
    if ($typeChecks.Count -ne 1 -or $valueChecks.Count -ne 1) {
        throw 'Expected exactly one numeric-type guard and one schema-value guard.'
    }
    return [scriptblock]::Create($typeChecks[0].Extent.Text + "`n" + $valueChecks[0].Extent.Text)
}

function New-Evidence {
    return @'
{
  "schemaVersion": 3,
  "runId": "11111111111111111111111111111111",
  "trust": {
    "mechanism": "project-p256-release-manifest",
    "releaseId": "qa-elevation-11111111111111111111111111111111",
    "manifestPayloadSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "diagnosticOnly": true
  },
  "brokerVerificationCount": 2,
  "diagnosticBuild": { "nonProduction": true, "privateKeyRemovedBeforeRun": true },
  "exactPayload": {
    "brokerProcessId": 101, "executionCount": 1,
    "leaseId": "11111111-1111-1111-1111-111111111111",
    "markerObserved": true, "markerValue": "1",
    "brokerManifestVerifiedWhileLocked": true,
    "brokerExitedNaturally": true, "brokerExitCode": 0
  },
  "tamperChecks": [
    { "field": "script", "errorCode": "NOT_AUTHORIZED", "markerUnchanged": true },
    { "field": "path", "errorCode": "NOT_AUTHORIZED", "markerUnchanged": true },
    { "field": "scope", "errorCode": "NOT_AUTHORIZED", "markerUnchanged": true },
    { "field": "timeout", "errorCode": "NOT_AUTHORIZED", "markerUnchanged": true }
  ],
  "expiry": {
    "brokerProcessId": 102, "durationMilliseconds": 5000,
    "leaseId": "22222222-2222-2222-2222-222222222222",
    "errorCode": "LEASE_EXPIRED", "startedMarkerObserved": true,
    "completedMarkerAbsent": true, "brokerManifestVerifiedWhileLocked": true,
    "brokerExitedNaturally": true, "brokerExitCode": 0
  }
}
'@ | ConvertFrom-Json
}

function Set-EvidenceField {
    param($Evidence, [string] $Path, $Value)
    $parts = $Path.Split('.')
    $parent = $Evidence
    for ($index = 0; $index -lt $parts.Length - 1; $index++) {
        $parent = $parent.($parts[$index])
    }
    $parent.($parts[-1]) = $Value
}

function Assert-GuardResult {
    param([scriptblock] $Guard, $Evidence, [bool] $ExpectedPass, [string] $Case)
    $releaseId = 'qa-elevation-11111111111111111111111111111111'
    $manifestPayloadSha256 = 'a' * 64
    $ExpiryMilliseconds = 5000
    $passed = $true
    try { & $Guard } catch { $passed = $false }
    if ($passed -ne $ExpectedPass) { throw "Unexpected schema-guard result: $Case" }
}

$checks = 0
foreach ($driver in @('run-signed-elevation-protocol-qa.ps1', 'run-authorized-lab-qa.ps1')) {
    $guard = Get-SchemaGuard -Ast $parsed[$driver]
    Assert-GuardResult -Guard $guard -Evidence (New-Evidence) -ExpectedPass $true -Case "$driver valid"
    $checks++
    foreach ($path in @('schemaVersion', 'brokerVerificationCount',
        'exactPayload.brokerProcessId', 'expiry.brokerProcessId',
        'exactPayload.executionCount', 'expiry.durationMilliseconds',
        'exactPayload.brokerExitCode', 'expiry.brokerExitCode')) {
        foreach ($badValue in @($null, $false, '0', [double]0)) {
            $evidence = New-Evidence
            Set-EvidenceField -Evidence $evidence -Path $path -Value $badValue
            Assert-GuardResult -Guard $guard -Evidence $evidence -ExpectedPass $false -Case "$driver $path type"
            $checks++
        }
    }
    foreach ($path in @('exactPayload.brokerManifestVerifiedWhileLocked',
        'expiry.brokerManifestVerifiedWhileLocked', 'exactPayload.brokerExitedNaturally',
        'expiry.brokerExitedNaturally', 'expiry.completedMarkerAbsent', 'trust.diagnosticOnly')) {
        $evidence = New-Evidence
        Set-EvidenceField -Evidence $evidence -Path $path -Value $false
        Assert-GuardResult -Guard $guard -Evidence $evidence -ExpectedPass $false -Case "$driver $path false"
        $checks++
    }
    foreach ($path in @('exactPayload.brokerExitCode', 'expiry.brokerExitCode')) {
        $evidence = New-Evidence
        Set-EvidenceField -Evidence $evidence -Path $path -Value 1
        Assert-GuardResult -Guard $guard -Evidence $evidence -ExpectedPass $false -Case "$driver $path nonzero"
        $checks++
    }
    $evidence = New-Evidence
    $evidence.tamperChecks[3].field = 'script'
    Assert-GuardResult -Guard $guard -Evidence $evidence -ExpectedPass $false -Case "$driver duplicate tamper"
    $checks++
    $evidence = New-Evidence
    $evidence.expiry.leaseId = $evidence.exactPayload.leaseId
    Assert-GuardResult -Guard $guard -Evidence $evidence -ExpectedPass $false -Case "$driver reused lease"
    $checks++
}
[ordered]@{
    scope = 'PowerShell parser and synthetic evidence-schema guards only; no Windows installation or UAC'
    powershellVersion = $PSVersionTable.PSVersion.ToString()
    parsedScripts = $parsed.Count
    passedChecks = $checks
} | ConvertTo-Json
