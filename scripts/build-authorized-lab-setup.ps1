[CmdletBinding()]
param(
    [string] $OutputDirectory,
    [string] $CertificateThumbprint,
    [switch] $CreateTrustedLabCertificate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSBoundParameters.ContainsKey('CertificateThumbprint') -or
    $PSBoundParameters.ContainsKey('CreateTrustedLabCertificate')) {
    throw 'CertificateThumbprint and CreateTrustedLabCertificate are retired. Lab builds use a fresh disposable project key and never change Windows certificate trust.'
}
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'The authorized-lab Setup must be built on Windows.'
}
if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne
    [Runtime.InteropServices.Architecture]::X64) {
    throw 'The authorized-lab Setup must be built on Windows x64.'
}

$companionRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $companionRoot 'artifacts\authorized-lab-setup'
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) {
    if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container) -or
        @(Get-ChildItem -LiteralPath $OutputDirectory -Force).Count -ne 0) {
        throw 'Use a new or empty authorized-lab output directory so snapshots cannot mix builds.'
    }
}
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'jts-companion-lab-build-{0}' -f [Guid]::NewGuid().ToString('N'))
$agentOutput = Join-Path $temporaryRoot 'agent'
$brokerOutput = Join-Path $temporaryRoot 'broker'
$setupOutput = Join-Path $temporaryRoot 'setup'
$toolOutput = Join-Path $temporaryRoot 'manifest-tool'
$privateKeyPath = Join-Path $temporaryRoot 'ephemeral-lab-private.pem'
$publicKeyPath = Join-Path $temporaryRoot 'JTS.WindowsCompanion.release-public.pem'
$releaseManifestPath = Join-Path $temporaryRoot 'JTS.WindowsCompanion.release.json'
$releaseId = 'authorized-lab-' + [Guid]::NewGuid().ToString('N')
$artifactName = 'JTS-Windows-Companion-2.0.0-win-x64-AUTHORIZED-LAB-ONLY.exe'

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory)] [string] $Executable,
        [Parameter(Mandatory)] [string[]] $Arguments
    )

    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $($LASTEXITCODE): $Executable"
    }
}

function Publish-SingleFile {
    param(
        [Parameter(Mandatory)] [string] $Project,
        [Parameter(Mandatory)] [string] $Destination,
        [string[]] $AdditionalProperties = @()
    )

    $arguments = @(
        'publish', $Project,
        '--configuration', 'Release',
        '--runtime', 'win-x64',
        '--self-contained', 'true',
        '--output', $Destination,
        '-p:PublishSingleFile=true',
        '-p:IncludeNativeLibrariesForSelfExtract=true',
        '-p:PublishTrimmed=false',
        '-p:DebugType=None',
        '-p:DebugSymbols=false',
        '-p:ContinuousIntegrationBuild=true',
        '--nologo'
    ) + $AdditionalProperties
    Invoke-CheckedCommand -Executable 'dotnet' -Arguments $arguments
}

try {
    New-Item -ItemType Directory -Path $agentOutput, $brokerOutput, $setupOutput, $toolOutput -Force | Out-Null
    $toolProject = Join-Path $companionRoot 'tools\JTS.WindowsCompanion.ReleaseManifestTool\JTS.WindowsCompanion.ReleaseManifestTool.csproj'
    Invoke-CheckedCommand -Executable 'dotnet' -Arguments @(
        'build', $toolProject, '--configuration', 'Release', '--output', $toolOutput, '--nologo'
    )
    $manifestTool = Join-Path $toolOutput 'JTS.WindowsCompanion.ReleaseManifestTool.dll'
    Invoke-CheckedCommand -Executable 'dotnet' -Arguments @(
        $manifestTool, 'keygen', '--private-key', $privateKeyPath
    )
    Invoke-CheckedCommand -Executable 'dotnet' -Arguments @(
        $manifestTool, 'public-key', '--private-key', $privateKeyPath, '--output', $publicKeyPath
    )
    $anchorProperties = @("-p:CompanionReleasePublicKeyPath=$publicKeyPath")
    $agentProject = Join-Path $companionRoot 'src\JTS.WindowsCompanion.Agent\JTS.WindowsCompanion.Agent.csproj'
    $brokerProject = Join-Path $companionRoot 'src\JTS.WindowsCompanion.UacBroker\JTS.WindowsCompanion.UacBroker.csproj'
    $setupProject = Join-Path $companionRoot 'src\JTS.WindowsCompanion.Setup\JTS.WindowsCompanion.Setup.csproj'
    Publish-SingleFile -Project $agentProject -Destination $agentOutput -AdditionalProperties $anchorProperties
    Publish-SingleFile -Project $brokerProject -Destination $brokerOutput -AdditionalProperties $anchorProperties

    $agentExecutable = Join-Path $agentOutput 'JTS.WindowsCompanion.Agent.exe'
    $brokerExecutable = Join-Path $brokerOutput 'JTS.WindowsCompanion.UacBroker.exe'
    Invoke-CheckedCommand -Executable 'dotnet' -Arguments @(
        $manifestTool, 'sign', '--private-key', $privateKeyPath,
        '--release-id', $releaseId, '--output', $releaseManifestPath,
        '--file', $agentExecutable, '--file', $brokerExecutable
    )
    Publish-SingleFile -Project $setupProject -Destination $setupOutput -AdditionalProperties ($anchorProperties + @(
        "-p:AgentPayloadPath=$agentExecutable",
        "-p:BrokerPayloadPath=$brokerExecutable",
        "-p:ReleaseManifestPath=$releaseManifestPath"
    ))
    $setupExecutable = Join-Path $setupOutput 'JTS.WindowsCompanion.Setup.exe'

    # Only these five public artifacts leave staging. Never copy the staging
    # directory or private key. The tester pins this exact local build snapshot.
    $artifacts = @(
        @{ role = 'agent'; source = $agentExecutable; relativePath = 'payloads/JTS.WindowsCompanion.Agent.exe' },
        @{ role = 'broker'; source = $brokerExecutable; relativePath = 'payloads/JTS.WindowsCompanion.UacBroker.exe' },
        @{ role = 'setup'; source = $setupExecutable; relativePath = $artifactName },
        @{ role = 'release-manifest'; source = $releaseManifestPath; relativePath = 'JTS.WindowsCompanion.release.json' },
        @{ role = 'release-public-key'; source = $publicKeyPath; relativePath = 'JTS.WindowsCompanion.release-public.pem' }
    )
    New-Item -ItemType Directory -Path $OutputDirectory, (Join-Path $OutputDirectory 'payloads') -Force | Out-Null
    $files = @($artifacts | ForEach-Object {
        $destination = Join-Path $OutputDirectory $_.relativePath
        Copy-Item -LiteralPath $_.source -Destination $destination -Force
        $file = Get-Item -LiteralPath $destination
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $destination).Hash.ToLowerInvariant()
        if ($hash -cne (Get-FileHash -Algorithm SHA256 -LiteralPath $_.source).Hash.ToLowerInvariant()) {
            throw 'A copied lab artifact does not match its completed build bytes.'
        }
        [ordered]@{
            role = $_.role
            fileName = $file.Name
            relativePath = $_.relativePath
            sha256 = $hash
            sizeBytes = [long]$file.Length
        }
    })
    $setupHash = ($files | Where-Object { $_.role -eq 'setup' }).sha256
    $sha256Path = Join-Path $OutputDirectory ([IO.Path]::ChangeExtension($artifactName, '.sha256'))
    $sha256Line = '{0}  {1}{2}' -f $setupHash, $artifactName, [Environment]::NewLine
    Set-Content -LiteralPath $sha256Path -Encoding ascii -NoNewline -Value $sha256Line
    Set-Content -LiteralPath (Join-Path $OutputDirectory 'AUTHORIZED-LAB-ONLY.txt') -Encoding utf8 -Value @(
        'AUTHORIZED LAB ONLY - NOT FOR DISTRIBUTION OR PRODUCTION RELEASE EVIDENCE'
        'This build uses a fresh disposable diagnostic release identity.'
        'Never embed these artifacts in or distribute them with the macOS app.'
        'No Windows certificate trust store was modified.'
    )

    $buildEvidence = [ordered]@{
        schemaVersion = 1
        evidenceKind = 'authorized-lab-diagnostic-build'
        releaseId = $releaseId
        productionIdentity = $false
        authenticodeRequired = $false
        createdUtc = [DateTime]::UtcNow.ToString('o')
        buildHost = [ordered]@{
            osDescription = [Runtime.InteropServices.RuntimeInformation]::OSDescription
            architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        }
        files = $files
    }
    $evidenceJson = $buildEvidence | ConvertTo-Json -Depth 6
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $evidenceBytes = $utf8.GetBytes($evidenceJson)
    if ($evidenceBytes.Length -gt 16384) {
        throw 'The diagnostic build evidence exceeds its 16 KiB contract.'
    }
    $buildEvidencePath = Join-Path $OutputDirectory 'build-evidence.json'
    [IO.File]::WriteAllBytes($buildEvidencePath, $evidenceBytes)
    $evidenceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $buildEvidencePath).Hash.ToLowerInvariant()

    Write-Warning 'AUTHORIZED LAB ONLY: disposable identity; never distribute or embed in the macOS app.'
    Write-Host "Authorized-lab Setup: $(Join-Path $OutputDirectory $artifactName)"
    Write-Host "SHA-256: $setupHash"
    Write-Host "Build evidence: $buildEvidencePath"
    Write-Host "Build evidence SHA-256: $evidenceHash"
} finally {
    if (Test-Path -LiteralPath $privateKeyPath) {
        Remove-Item -LiteralPath $privateKeyPath -Force
    }
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
