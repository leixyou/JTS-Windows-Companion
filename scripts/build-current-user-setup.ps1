[CmdletBinding()]
param(
    [string] $OutputDirectory,
    [string] $ReleasePrivateKeyPath = $env:JTS_RELEASE_PRIVATE_KEY_PATH,
    [string] $ReleaseId = '2.0.0',
    [string] $CertificateThumbprint = $env:JTS_SIGN_CERT_SHA1,
    [string] $TimestampUrl = $env:JTS_SIGN_TIMESTAMP_URL,
    [switch] $AllowUnsignedDevelopmentBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-companion-evidence.ps1')

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'The Windows Companion setup must be published on Windows.'
}

if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne
    [System.Runtime.InteropServices.Architecture]::X64) {
    throw 'The Windows Companion setup must be published on a Windows x64 runner.'
}

$companionRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $companionRoot 'artifacts\current-user-setup'
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)

$agentProject = Join-Path $companionRoot 'src\JTS.WindowsCompanion.Agent\JTS.WindowsCompanion.Agent.csproj'
$brokerProject = Join-Path $companionRoot 'src\JTS.WindowsCompanion.UacBroker\JTS.WindowsCompanion.UacBroker.csproj'
$setupProject = Join-Path $companionRoot 'src\JTS.WindowsCompanion.Setup\JTS.WindowsCompanion.Setup.csproj'
$manifestToolProject = Join-Path $companionRoot 'tools\JTS.WindowsCompanion.ReleaseManifestTool\JTS.WindowsCompanion.ReleaseManifestTool.csproj'
$artifactName = if ($AllowUnsignedDevelopmentBuild) {
    'JTS-Windows-Companion-2.0.0-win-x64-UNSIGNED-DEVELOPMENT.exe'
} else {
    'JTS-Windows-Companion-2.0.0-win-x64.exe'
}
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("jts-companion-build-{0}" -f [Guid]::NewGuid().ToString('N'))
$agentOutput = Join-Path $temporaryRoot 'agent'
$brokerOutput = Join-Path $temporaryRoot 'broker'
$setupOutput = Join-Path $temporaryRoot 'setup'
$toolOutput = Join-Path $temporaryRoot 'manifest-tool'
$publicKeyPath = Join-Path $temporaryRoot 'release-public-key.pem'
$releaseManifestPath = Join-Path $temporaryRoot 'JTS.WindowsCompanion.release.json'

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory)]
        [string] $Executable,
        [Parameter(Mandatory)]
        [string[]] $Arguments
    )

    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $($LASTEXITCODE): $Executable"
    }
}

function Publish-SingleFile {
    param(
        [Parameter(Mandatory)]
        [string] $Project,
        [Parameter(Mandatory)]
        [string] $Destination,
        [string[]] $AdditionalProperties = @()
    )

    $arguments = @(
        'publish',
        $Project,
        '--configuration', 'Release',
        '--runtime', 'win-x64',
        '--self-contained', 'true',
        '--output', $Destination,
        '-p:PublishSingleFile=true',
        '-p:IncludeNativeLibrariesForSelfExtract=true',
        '-p:PublishTrimmed=false',
        '-p:DebugType=None',
        '-p:DebugSymbols=false',
        '-p:ContinuousIntegrationBuild=true'
    ) + $AdditionalProperties
    Invoke-CheckedCommand -Executable 'dotnet' -Arguments $arguments
}

function Get-SignTool {
    $identity = Get-JTSTrustedSignTool
    if ($null -eq $identity) {
        throw 'A trusted Microsoft-signed x64 signtool.exe under the canonical Windows Kits directory is required.'
    }
    Assert-JTSTrustedSignToolIdentity -Identity $identity
    return $identity
}

function Sign-AndVerify {
    param(
        [Parameter(Mandatory)]
        $SignTool,
        [Parameter(Mandatory)]
        [string] $Path
    )

    Assert-JTSTrustedSignToolIdentity -Identity $SignTool
    Invoke-CheckedCommand -Executable ([string]$SignTool.path) -Arguments @(
        'sign',
        '/sha1', $CertificateThumbprint,
        '/fd', 'SHA256',
        '/tr', $TimestampUrl,
        '/td', 'SHA256',
        '/v',
        $Path
    )
    Assert-JTSTrustedSignToolIdentity -Identity $SignTool
    Invoke-CheckedCommand `
        -Executable ([string]$SignTool.path) `
        -Arguments @('verify', '/pa', '/all', '/v', $Path)
    Assert-JTSTrustedSignToolIdentity -Identity $SignTool
}

function Assert-SameSigner {
    param(
        [Parameter(Mandatory)]
        [string[]] $Paths
    )

    $signatures = $Paths | ForEach-Object { Get-AuthenticodeSignature -LiteralPath $_ }
    if ($signatures | Where-Object { $_.Status -ne [System.Management.Automation.SignatureStatus]::Valid }) {
        throw 'One or more Windows Companion binaries do not have a valid Authenticode signature.'
    }

    $thumbprints = @($signatures | ForEach-Object { $_.SignerCertificate.Thumbprint } | Select-Object -Unique)
    if ($thumbprints.Count -ne 1) {
        throw 'Agent, UAC broker, and setup must be signed by the same certificate.'
    }
}

if ([string]::IsNullOrWhiteSpace($ReleasePrivateKeyPath)) {
    if (-not $AllowUnsignedDevelopmentBuild) {
        throw 'Provide -ReleasePrivateKeyPath or JTS_RELEASE_PRIVATE_KEY_PATH for a distributable release. Authenticode alone is not a release identity.'
    }
} else {
    if ($AllowUnsignedDevelopmentBuild) {
        throw 'Do not combine a production release private key with -AllowUnsignedDevelopmentBuild.'
    }
    $ReleasePrivateKeyPath = [IO.Path]::GetFullPath($ReleasePrivateKeyPath)
    if (-not (Test-Path -LiteralPath $ReleasePrivateKeyPath -PathType Leaf)) {
        throw 'The external release private key file does not exist.'
    }
}
if ($ReleaseId -notmatch '\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z') {
    throw 'The release ID must be 1-64 portable ASCII name characters and start with a letter or digit.'
}

$hasCertificate = -not [string]::IsNullOrWhiteSpace($CertificateThumbprint)
$hasTimestamp = -not [string]::IsNullOrWhiteSpace($TimestampUrl)
if ($hasCertificate -ne $hasTimestamp) {
    throw 'Optional Authenticode signing requires both CertificateThumbprint and TimestampUrl; partial signing configuration is not allowed.'
}
$useAuthenticode = $hasCertificate -and $hasTimestamp
if ($useAuthenticode) {
    $CertificateThumbprint = $CertificateThumbprint.Replace(' ', '')
    if ($CertificateThumbprint.Length -ne 40 -or $CertificateThumbprint -notmatch '\A[0-9A-Fa-f]{40}\z') {
        throw 'The signing certificate thumbprint must be exactly 40 hexadecimal characters.'
    }
    $timestampUri = [Uri] $TimestampUrl
    if (-not $timestampUri.IsAbsoluteUri -or
        $timestampUri.Scheme -notin @([Uri]::UriSchemeHttp, [Uri]::UriSchemeHttps)) {
        throw 'The timestamp URL must be an absolute HTTP or HTTPS URI.'
    }
}

try {
    New-Item -ItemType Directory -Path $agentOutput, $brokerOutput, $setupOutput, $toolOutput -Force | Out-Null

    # Build only this independent .NET 8 tool, then validate the key before any
    # expensive Windows payload publish. Private key bytes never enter MSBuild.
    Invoke-CheckedCommand -Executable 'dotnet' -Arguments @(
        'build', $manifestToolProject, '--configuration', 'Release', '--output', $toolOutput, '--nologo'
    )
    $manifestTool = Join-Path $toolOutput 'JTS.WindowsCompanion.ReleaseManifestTool.dll'
    if ($AllowUnsignedDevelopmentBuild) {
        $ReleasePrivateKeyPath = Join-Path $temporaryRoot 'development-only-private-key.pem'
        Invoke-CheckedCommand -Executable 'dotnet' -Arguments @(
            $manifestTool, 'keygen', '--private-key', $ReleasePrivateKeyPath
        )
        $ReleaseId = "development-$([Guid]::NewGuid().ToString('N'))"
    }
    Invoke-CheckedCommand -Executable 'dotnet' -Arguments @(
        $manifestTool, 'public-key', '--private-key', $ReleasePrivateKeyPath, '--output', $publicKeyPath
    )
    $anchorProperties = @("-p:CompanionReleasePublicKeyPath=$publicKeyPath")

    $signTool = $null
    if ($useAuthenticode) {
        $signTool = Get-SignTool
    }

    Publish-SingleFile -Project $agentProject -Destination $agentOutput -AdditionalProperties $anchorProperties
    Publish-SingleFile -Project $brokerProject -Destination $brokerOutput -AdditionalProperties $anchorProperties

    $agentExecutable = Join-Path $agentOutput 'JTS.WindowsCompanion.Agent.exe'
    $brokerExecutable = Join-Path $brokerOutput 'JTS.WindowsCompanion.UacBroker.exe'
    if (-not (Test-Path -LiteralPath $agentExecutable -PathType Leaf) -or
        -not (Test-Path -LiteralPath $brokerExecutable -PathType Leaf)) {
        throw 'The Agent or UAC broker single-file payload was not produced.'
    }

    if ($useAuthenticode) {
        Sign-AndVerify -SignTool $signTool -Path $agentExecutable
        Sign-AndVerify -SignTool $signTool -Path $brokerExecutable
    }

    # Hash the FINAL payload bytes, including optional Authenticode signatures.
    Invoke-CheckedCommand -Executable 'dotnet' -Arguments @(
        $manifestTool, 'sign', '--private-key', $ReleasePrivateKeyPath,
        '--release-id', $ReleaseId, '--output', $releaseManifestPath,
        '--file', $agentExecutable, '--file', $brokerExecutable
    )

    Publish-SingleFile -Project $setupProject -Destination $setupOutput -AdditionalProperties ($anchorProperties + @(
        "-p:AgentPayloadPath=$agentExecutable",
        "-p:BrokerPayloadPath=$brokerExecutable",
        "-p:ReleaseManifestPath=$releaseManifestPath"
    ))

    $setupExecutable = Join-Path $setupOutput 'JTS.WindowsCompanion.Setup.exe'
    if (-not (Test-Path -LiteralPath $setupExecutable -PathType Leaf)) {
        throw 'The Windows Companion setup executable was not produced.'
    }

    if ($useAuthenticode) {
        Sign-AndVerify -SignTool $signTool -Path $setupExecutable
        Assert-SameSigner -Paths @($agentExecutable, $brokerExecutable, $setupExecutable)
    }

    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $artifactPath = Join-Path $OutputDirectory $artifactName
    Copy-Item -LiteralPath $setupExecutable -Destination $artifactPath -Force

    $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $artifactPath
    $file = Get-Item -LiteralPath $artifactPath
    $manifestPath = Join-Path $OutputDirectory ([System.IO.Path]::ChangeExtension($artifactName, '.sha256'))
    Set-Content -LiteralPath $manifestPath -Encoding ascii -NoNewline -Value (
        "{0}  {1}`n" -f $hash.Hash.ToLowerInvariant(), $file.Name
    )

    if ($AllowUnsignedDevelopmentBuild) {
        $warningPath = Join-Path $OutputDirectory 'UNSIGNED-DEVELOPMENT-BUILD.txt'
        Set-Content -LiteralPath $warningPath -Encoding utf8 -Value @(
            'This artifact is for compilation and packaging verification only.'
            'It uses a disposable development release identity, not the production release identity.'
            'It must never be embedded in or distributed with the macOS app.'
            'Do not distribute this artifact.'
        )
        Write-Warning 'NON-DISTRIBUTABLE DEVELOPMENT BUILD: disposable identity; never embed this Setup in the macOS app.'
    }

    Write-Host "Windows Companion setup: $artifactPath"
    Write-Host "Release manifest identity: $ReleaseId"
    Write-Host "Authenticode signing enabled: $useAuthenticode"
    Write-Host "SHA-256: $($hash.Hash.ToLowerInvariant())"
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
