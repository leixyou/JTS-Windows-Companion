Set-StrictMode -Version Latest

function ConvertTo-JTSCertificateEvidence {
    param($Certificate)

    if ($null -eq $Certificate) {
        return $null
    }

    return [pscustomobject][ordered]@{
        subject = $Certificate.Subject
        issuer = $Certificate.Issuer
        serialNumber = $Certificate.SerialNumber
        thumbprint = $Certificate.Thumbprint
        notBeforeUtc = $Certificate.NotBefore.ToUniversalTime().ToString('o')
        notAfterUtc = $Certificate.NotAfter.ToUniversalTime().ToString('o')
    }
}

function Get-JTSAuthenticodeEvidence {
    param(
        [Parameter(Mandatory)] [string] $Role,
        [Parameter(Mandatory)] [string] $Path
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw "The $Role Authenticode evidence file is missing: $fullPath"
    }

    $file = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "The $Role Authenticode evidence file is a reparse point: $fullPath"
    }
    $sha256Before = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $fullPath -ErrorAction Stop).Hash.ToLowerInvariant()
    $signature = Get-AuthenticodeSignature -LiteralPath $fullPath -ErrorAction Stop
    $fileAfter = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    $sha256After = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $fullPath -ErrorAction Stop).Hash.ToLowerInvariant()
    if (($fileAfter.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $fileAfter.Length -ne $file.Length -or
        $sha256After -ne $sha256Before) {
        throw "The $Role file changed during Authenticode evidence capture: $fullPath"
    }
    $signatureType = if ($null -ne $signature.PSObject.Properties['SignatureType']) {
        $signature.SignatureType.ToString()
    } else {
        $null
    }
    $isOSBinary = if ($null -ne $signature.PSObject.Properties['IsOSBinary']) {
        [bool]$signature.IsOSBinary
    } else {
        $false
    }
    return [pscustomobject][ordered]@{
        role = $Role
        path = $fullPath
        fileName = $file.Name
        lengthBytes = $fileAfter.Length
        sha256 = $sha256After
        signatureStatus = $signature.Status.ToString()
        signatureStatusMessage = $signature.StatusMessage
        signatureType = $signatureType
        isOSBinary = $isOSBinary
        hasTimestamp = $null -ne $signature.TimeStamperCertificate
        signerCertificate = ConvertTo-JTSCertificateEvidence -Certificate $signature.SignerCertificate
        timeStamperCertificate = ConvertTo-JTSCertificateEvidence -Certificate $signature.TimeStamperCertificate
    }
}

function Get-JTSTrustedSignTool {
    $programFilesX86 = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::ProgramFilesX86)
    if ([string]::IsNullOrWhiteSpace($programFilesX86)) {
        return $null
    }
    $kitsRoot = [IO.Path]::GetFullPath(
        (Join-Path $programFilesX86 'Windows Kits\10\bin'))
    if (-not (Test-Path -LiteralPath $kitsRoot -PathType Container)) {
        return $null
    }

    $versionDirectories = @(Get-ChildItem -LiteralPath $kitsRoot -Directory -ErrorAction Stop |
        Where-Object { $_.Name -match '\A[0-9]+(?:\.[0-9]+){1,3}\z' } |
        Sort-Object { [Version]$_.Name } -Descending)
    $signToolPath = @($versionDirectories |
        ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1)
    if ($signToolPath.Count -eq 0) {
        return $null
    }

    $path = [IO.Path]::GetFullPath([string]$signToolPath[0])
    $rootPrefix = $kitsRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) +
        [IO.Path]::DirectorySeparatorChar
    if (-not $path.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The selected signtool.exe is outside the canonical Windows Kits directory.'
    }
    $file = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The selected Windows Kits signtool.exe is a reparse point.'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
    $subject = [string]$signature.SignerCertificate.Subject
    if ($file.VersionInfo.OriginalFilename -ine 'signtool.exe' -or
        $signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate -or
        $subject -notmatch '(?:\A|,\s*)(?:CN|O)=Microsoft Corporation(?:,|\z)') {
        throw 'The canonical Windows Kits signtool.exe does not have a valid Microsoft signature.'
    }
    return [pscustomobject][ordered]@{
        kitsRoot = $kitsRoot
        path = $path
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $path -ErrorAction Stop).Hash.ToLowerInvariant()
        signatureStatus = $signature.Status.ToString()
        signerSubject = $subject
        signerThumbprint = $signature.SignerCertificate.Thumbprint
        originalFilename = $file.VersionInfo.OriginalFilename
        productVersion = $file.VersionInfo.ProductVersion
    }
}

function Assert-JTSTrustedSignToolIdentity {
    param([Parameter(Mandatory)] $Identity)

    $path = [IO.Path]::GetFullPath([string]$Identity.path)
    $kitsRoot = [IO.Path]::GetFullPath([string]$Identity.kitsRoot)
    $rootPrefix = $kitsRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) +
        [IO.Path]::DirectorySeparatorChar
    if (-not $path.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The trusted signtool.exe identity escaped the Windows Kits directory.'
    }
    $file = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    $signature = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
    $actualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $path -ErrorAction Stop).Hash.ToLowerInvariant()
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $file.VersionInfo.OriginalFilename -ine 'signtool.exe' -or
        $file.VersionInfo.OriginalFilename -ne [string]$Identity.originalFilename -or
        $file.VersionInfo.ProductVersion -ne [string]$Identity.productVersion -or
        $actualSha256 -ne [string]$Identity.sha256 -or
        $signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint -ne [string]$Identity.signerThumbprint -or
        [string]$signature.SignerCertificate.Subject -notmatch
            '(?:\A|,\s*)(?:CN|O)=Microsoft Corporation(?:,|\z)') {
        throw 'The trusted Windows Kits signtool.exe identity changed or is invalid.'
    }
}

function Invoke-JTSSignToolEvidence {
    param(
        [Parameter(Mandatory)] [object[]] $Files,
        [Parameter(Mandatory)] [string] $OutputDirectory,
        [switch] $RequireSuccess
    )

    $OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $signTool = Get-JTSTrustedSignTool
    $results = New-Object Collections.Generic.List[object]

    foreach ($file in $Files) {
        $role = [string]$file.role
        $path = [IO.Path]::GetFullPath([string]$file.path)
        $inputFile = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if (($inputFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "The signtool input is a reparse point for role ${role}: $path"
        }
        $inputSha256Before = (Get-FileHash -Algorithm SHA256 `
            -LiteralPath $path -ErrorAction Stop).Hash.ToLowerInvariant()
        $safeRole = $role -replace '[^A-Za-z0-9_.-]', '-'
        $logPath = Join-Path $OutputDirectory ("signtool-{0}.log" -f $safeRole)
        $arguments = @('verify', '/pa', '/all', '/v', $path)
        $exitCode = $null
        $succeeded = $false
        $logLines = @()

        if ($null -eq $signTool) {
            $logLines = @(
                'signtool.exe was not found.'
                'Install the Windows SDK to produce native Authenticode policy verification evidence.'
            )
        } else {
            Assert-JTSTrustedSignToolIdentity -Identity $signTool
            $logLines = @(& ([string]$signTool.path) @arguments 2>&1)
            $exitCode = $LASTEXITCODE
            Assert-JTSTrustedSignToolIdentity -Identity $signTool
            $succeeded = $exitCode -eq 0
        }
        $inputFileAfter = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        $inputSha256After = (Get-FileHash -Algorithm SHA256 `
            -LiteralPath $path -ErrorAction Stop).Hash.ToLowerInvariant()
        if (($inputFileAfter.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $inputFileAfter.Length -ne $inputFile.Length -or
            $inputSha256After -ne $inputSha256Before) {
            throw "The signtool input changed during verification for role ${role}: $path"
        }
        $logStream = [IO.File]::Open(
            $logPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        $logWriter = [IO.StreamWriter]::new($logStream, [Text.UTF8Encoding]::new($false))
        try {
            foreach ($line in $logLines) {
                $logWriter.WriteLine([string]$line)
            }
        } finally {
            $logWriter.Dispose()
        }
        $logFile = Get-Item -LiteralPath $logPath -Force -ErrorAction Stop
        if (($logFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "The signtool evidence log is a reparse point: $logPath"
        }
        $logSha256 = (Get-FileHash -Algorithm SHA256 `
            -LiteralPath $logPath -ErrorAction Stop).Hash.ToLowerInvariant()

        $results.Add([pscustomobject][ordered]@{
            role = $role
            path = $path
            signToolAvailable = $null -ne $signTool
            signToolTrusted = $null -ne $signTool
            signToolPath = if ($null -eq $signTool) { $null } else { $signTool.path }
            signToolSha256 = if ($null -eq $signTool) { $null } else { $signTool.sha256 }
            signToolSignerSubject = if ($null -eq $signTool) { $null } else { $signTool.signerSubject }
            signToolSignerThumbprint = if ($null -eq $signTool) { $null } else { $signTool.signerThumbprint }
            signToolOriginalFilename = if ($null -eq $signTool) { $null } else { $signTool.originalFilename }
            signToolProductVersion = if ($null -eq $signTool) { $null } else { $signTool.productVersion }
            inputLengthBytes = $inputFileAfter.Length
            inputSha256 = $inputSha256After
            arguments = $arguments
            exitCode = $exitCode
            succeeded = $succeeded
            logPath = $logPath
            logLengthBytes = $logFile.Length
            logSha256 = $logSha256
        })
    }

    if ($null -ne $signTool -and @($results | Where-Object { -not $_.succeeded }).Count -ne 0) {
        throw 'One or more native signtool Authenticode policy verifications did not pass.'
    }
    if ($RequireSuccess -and $null -eq $signTool) {
        throw 'signtool.exe is required for this Authenticode evidence run but was not found.'
    }

    return $results.ToArray()
}

function Get-JTSProductionReleaseManifest {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $ExpectedManifestSha256,
        [Parameter(Mandatory)] [string] $ExpectedSourceCommit,
        [Parameter(Mandatory)] [string] $ExpectedPublisherThumbprint
    )

    if ($ExpectedManifestSha256 -notmatch '\A[0-9a-fA-F]{64}\z' -or
        $ExpectedSourceCommit -notmatch '\A[0-9a-f]{40}\z' -or
        $ExpectedPublisherThumbprint -notmatch '\A[0-9a-fA-F]{40}\z') {
        throw 'The pre-registered production manifest identity is malformed.'
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    $file = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The production release manifest must not be a reparse point.'
    }
    if ($file.Length -le 0 -or $file.Length -gt 1MB) {
        throw 'The production release manifest size is invalid.'
    }

    # Read once, then bind both the digest and JSON object to these exact bytes.
    # Hashing the path and reading it again would permit a replacement between
    # the two operations to detach the parsed release roles from the
    # pre-registered digest.
    $manifestBytes = [IO.File]::ReadAllBytes($fullPath)
    if ($manifestBytes.LongLength -ne $file.Length) {
        throw 'The production release manifest changed while it was being read.'
    }
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $manifestDigest = $sha256.ComputeHash($manifestBytes)
    } finally {
        $sha256.Dispose()
    }
    $actualManifestSha256 = ([BitConverter]::ToString($manifestDigest)).Replace('-', '').ToLowerInvariant()
    if ($actualManifestSha256 -ne $ExpectedManifestSha256.ToLowerInvariant()) {
        throw 'The production release manifest does not match its pre-registered SHA-256.'
    }
    try {
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $manifestJson = $utf8.GetString($manifestBytes)
        $document = ConvertFrom-Json -InputObject $manifestJson -ErrorAction Stop
    } catch {
        throw 'The production release manifest is not valid strict UTF-8 JSON.'
    }
    $expectedThumbprint = $ExpectedPublisherThumbprint.ToUpperInvariant()
    if ($document.schema -ne 'jts-windows-companion-production-signing-v1' -or
        $document.sourceCommit -ne $ExpectedSourceCommit -or
        ([string]$document.publisherThumbprint).ToUpperInvariant() -ne $expectedThumbprint) {
        throw 'The production release manifest source or publisher identity is unexpected.'
    }

    $requiredRoles = @(
        'production-candidate-setup',
        'production-installed-agent',
        'production-installed-uac-broker',
        'production-installed-setup'
    )
    $filesByRole = @{}
    foreach ($record in @($document.files)) {
        $role = [string]$record.role
        if ($role -notin $requiredRoles -or $filesByRole.ContainsKey($role) -or
            [string]$record.sha256 -notmatch '\A[0-9a-f]{64}\z' -or
            [string]::IsNullOrWhiteSpace([string]$record.fileName) -or
            [string]$record.fileName -notmatch '\A[A-Za-z0-9_.-]+\.exe\z' -or
            [IO.Path]::GetFileName([string]$record.fileName) -ne [string]$record.fileName) {
            throw "Unexpected, duplicate, or malformed production manifest role: $role"
        }
        $filesByRole[$role] = $record
    }
    if ($filesByRole.Count -ne $requiredRoles.Count) {
        throw 'The production release manifest does not contain the exact required role set.'
    }
    return [pscustomobject][ordered]@{
        path = $fullPath
        sha256 = $actualManifestSha256
        sourceCommit = $ExpectedSourceCommit
        publisherThumbprint = $expectedThumbprint
        filesByRole = $filesByRole
    }
}

function Assert-JTSProductionAuthenticodeEvidence {
    param(
        [Parameter(Mandatory)] [object[]] $AuthenticodeEvidence,
        [Parameter(Mandatory)] [object[]] $SignToolEvidence,
        [Parameter(Mandatory)] [string] $ReleaseManifestPath,
        [Parameter(Mandatory)] [string] $ExpectedReleaseManifestSha256,
        [Parameter(Mandatory)] [string] $ExpectedSourceCommit,
        [Parameter(Mandatory)] [string] $ExpectedPublisherThumbprint,
        [Parameter(Mandatory)] [string] $RunId
    )

    if ($RunId -notmatch '\A[0-9]{8}T[0-9]{6}Z\z') {
        throw 'The production signing evidence run ID is malformed.'
    }
    $requiredRoles = @(
        'production-candidate-setup',
        'production-installed-agent',
        'production-installed-uac-broker',
        'production-installed-setup'
    )
    $manifest = Get-JTSProductionReleaseManifest `
        -Path $ReleaseManifestPath `
        -ExpectedManifestSha256 $ExpectedReleaseManifestSha256 `
        -ExpectedSourceCommit $ExpectedSourceCommit `
        -ExpectedPublisherThumbprint $ExpectedPublisherThumbprint
    $authenticodeByRole = @{}
    foreach ($record in $AuthenticodeEvidence) {
        $role = [string]$record.role
        if ($role -notin $requiredRoles -or $authenticodeByRole.ContainsKey($role)) {
            throw "Unexpected or duplicate production Authenticode role: $role"
        }
        if ($record.signatureStatus -ne 'Valid' -or
            [string]$record.sha256 -notmatch '\A[0-9a-f]{64}\z' -or
            $null -eq $record.signerCertificate -or
            [string]::IsNullOrWhiteSpace([string]$record.signerCertificate.thumbprint) -or
            ([string]$record.signerCertificate.thumbprint).ToUpperInvariant() -ne
                $manifest.publisherThumbprint -or
            [string]$record.sha256 -ne [string]$manifest.filesByRole[$role].sha256 -or
            [IO.Path]::GetFileName([string]$record.path) -ne
                [string]$manifest.filesByRole[$role].fileName -or
            $record.hasTimestamp -ne $true -or
            $null -eq $record.timeStamperCertificate) {
            throw "Production Authenticode or timestamp evidence is incomplete for role: $role"
        }
        $authenticodeByRole[$role] = $record
    }
    if ($authenticodeByRole.Count -ne $requiredRoles.Count) {
        throw 'Production Authenticode evidence does not contain the exact required role set.'
    }
    $thumbprints = @($AuthenticodeEvidence |
        ForEach-Object { ([string]$_.signerCertificate.thumbprint).ToUpperInvariant() } |
        Select-Object -Unique)
    if ($thumbprints.Count -ne 1 -or $thumbprints[0] -ne $manifest.publisherThumbprint) {
        throw 'Production Companion files do not match the pre-registered publisher certificate.'
    }

    $trustedSignTool = Get-JTSTrustedSignTool
    if ($null -eq $trustedSignTool) {
        throw 'A trusted Microsoft Windows Kits signtool.exe is required for production evidence.'
    }
    Assert-JTSTrustedSignToolIdentity -Identity $trustedSignTool
    $signToolByRole = @{}
    foreach ($record in $SignToolEvidence) {
        $role = [string]$record.role
        if ($role -notin $requiredRoles -or $signToolByRole.ContainsKey($role)) {
            throw "Unexpected or duplicate production signtool role: $role"
        }
        $logPath = [IO.Path]::GetFullPath([string]$record.logPath)
        if (-not (Test-Path -LiteralPath $logPath -PathType Leaf)) {
            throw "Production signtool evidence log is missing for role: $role"
        }
        $logFile = Get-Item -LiteralPath $logPath -Force -ErrorAction Stop
        if (($logFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Production signtool evidence log is a reparse point for role: $role"
        }
        $liveLogSha256 = (Get-FileHash -Algorithm SHA256 `
            -LiteralPath $logPath -ErrorAction Stop).Hash.ToLowerInvariant()
        $recordedFilePath = [IO.Path]::GetFullPath([string]$record.path)
        $liveInputFile = Get-Item -LiteralPath $recordedFilePath -Force -ErrorAction Stop
        if (($liveInputFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Production signtool input is a reparse point for role: $role"
        }
        $liveInputSha256 = (Get-FileHash -Algorithm SHA256 `
            -LiteralPath $recordedFilePath -ErrorAction Stop).Hash.ToLowerInvariant()
        $expectedSignToolArguments = @('verify', '/pa', '/all', '/v', $recordedFilePath)
        $recordedSignToolArguments = @($record.arguments)
        $signToolArgumentsMatch = $recordedSignToolArguments.Count -eq
                $expectedSignToolArguments.Count -and
            ($recordedSignToolArguments -join [char]0) -ceq
                ($expectedSignToolArguments -join [char]0)
        if ($record.signToolAvailable -ne $true -or
            $record.signToolTrusted -ne $true -or
            [IO.Path]::GetFullPath([string]$record.signToolPath) -ne
                [IO.Path]::GetFullPath([string]$trustedSignTool.path) -or
            [string]$record.signToolSha256 -ne [string]$trustedSignTool.sha256 -or
            [string]$record.signToolSignerThumbprint -ne
                [string]$trustedSignTool.signerThumbprint -or
            [string]$record.signToolSignerSubject -ne
                [string]$trustedSignTool.signerSubject -or
            [string]$record.signToolOriginalFilename -ne
                [string]$trustedSignTool.originalFilename -or
            [string]$record.signToolProductVersion -ne
                [string]$trustedSignTool.productVersion -or
            -not $signToolArgumentsMatch -or
            $record.succeeded -ne $true -or
            $record.exitCode -ne 0 -or
            [int64]$record.inputLengthBytes -ne $liveInputFile.Length -or
            [int64]$record.inputLengthBytes -ne
                [int64]$authenticodeByRole[$role].lengthBytes -or
            [string]$record.inputSha256 -ne $liveInputSha256 -or
            [string]$record.inputSha256 -ne
                [string]$authenticodeByRole[$role].sha256 -or
            [int64]$record.logLengthBytes -ne $logFile.Length -or
            [string]$record.logSha256 -notmatch '\A[0-9a-f]{64}\z' -or
            $liveLogSha256 -ne [string]$record.logSha256 -or
            $recordedFilePath -ne
                [IO.Path]::GetFullPath([string]$authenticodeByRole[$role].path)) {
            throw "Production signtool evidence failed or is path-mismatched for role: $role"
        }
        $signToolByRole[$role] = $record
    }
    if ($signToolByRole.Count -ne $requiredRoles.Count) {
        throw 'Production signtool evidence does not contain the exact required role set.'
    }
    $roleSha256 = [ordered]@{}
    foreach ($role in $requiredRoles) {
        $roleSha256[$role] = [string]$manifest.filesByRole[$role].sha256
    }
    $windows = @(Get-CimInstance Win32_OperatingSystem -ErrorAction Stop |
        Select-Object Caption, Version, BuildNumber, OSArchitecture)
    if ($windows.Count -ne 1 -or
        [string]::IsNullOrWhiteSpace([string]$windows[0].Version) -or
        [string]::IsNullOrWhiteSpace([string]$windows[0].BuildNumber)) {
        throw 'The production signing evidence could not bind one Windows version and build.'
    }
    return [pscustomobject][ordered]@{
        status = 'passed'
        runId = $RunId
        capturedAtUtc = [DateTime]::UtcNow.ToString('o')
        computerName = $env:COMPUTERNAME
        currentUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        windows = $windows[0]
        sourceCommit = $manifest.sourceCommit
        publisherThumbprint = $manifest.publisherThumbprint
        releaseManifestPath = $manifest.path
        releaseManifestSha256 = $manifest.sha256
        roleSha256 = [pscustomobject]$roleSha256
    }
}

function Get-JTSCompanionProcessIdentityKeys {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Processes
    )

    return @($Processes | ForEach-Object {
        $processId = if ($null -ne $_.PSObject.Properties['processId']) {
            $_.processId
        } else {
            $_.ProcessId
        }
        $executablePath = if ($null -ne $_.PSObject.Properties['executablePath']) {
            [string]$_.executablePath
        } else {
            [string]$_.ExecutablePath
        }
        $creationTimeUtc = if ($null -ne $_.PSObject.Properties['creationTimeUtc']) {
            [string]$_.creationTimeUtc
        } else {
            ([DateTime]$_.CreationDate).ToUniversalTime().ToString('o')
        }
        '{0}|{1}|{2}' -f $processId,
            ([IO.Path]::GetFullPath($executablePath)).ToLowerInvariant(),
            $creationTimeUtc
    } | Sort-Object)
}

function Assert-JTSCompanionProcessIdentitySet {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $ExpectedIdentityKeys,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Processes,
        [Parameter(Mandatory)] [string] $Stage,
        [Parameter(Mandatory)] [string] $Checkpoint
    )

    $actualIdentityKeys = @(Get-JTSCompanionProcessIdentityKeys -Processes $Processes)
    $differences = @(if ($ExpectedIdentityKeys.Count -ne $actualIdentityKeys.Count) {
        [pscustomobject]@{ reason = 'identity-count-mismatch' }
    } elseif ($ExpectedIdentityKeys.Count -gt 0) {
        Compare-Object -ReferenceObject $ExpectedIdentityKeys `
            -DifferenceObject $actualIdentityKeys
    })
    if ($ExpectedIdentityKeys.Count -ne $actualIdentityKeys.Count -or
        $differences.Count -ne 0) {
        throw "The monitored Companion process set changed at '$Checkpoint' during '$Stage' evidence capture."
    }
}

function Get-JTSCompanionEndpointSnapshot {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Processes
    )

    $processIds = @{}
    foreach ($process in $Processes) {
        $processId = if ($null -ne $process.PSObject.Properties['processId']) {
            [int64]$process.processId
        } else {
            [int64]$process.ProcessId
        }
        $processIds[$processId] = $true
    }

    # Both complete tables are queried with terminating errors. A failed query
    # must never be flattened into false zero-endpoint evidence.
    $allTcpEndpoints = @(Get-NetTCPConnection -ErrorAction Stop)
    $allUdpEndpoints = @(Get-NetUDPEndpoint -ErrorAction Stop)
    $tcpEndpoints = @($allTcpEndpoints |
        Where-Object { $processIds.ContainsKey([int64]$_.OwningProcess) } |
        ForEach-Object {
            [pscustomobject][ordered]@{
                processId = [int64]$_.OwningProcess
                LocalAddress = [string]$_.LocalAddress
                LocalPort = [int]$_.LocalPort
                RemoteAddress = [string]$_.RemoteAddress
                RemotePort = [int]$_.RemotePort
                State = [string]$_.State
            }
        } | Sort-Object processId, LocalAddress, LocalPort, RemoteAddress, RemotePort, State)
    $udpEndpoints = @($allUdpEndpoints |
        Where-Object { $processIds.ContainsKey([int64]$_.OwningProcess) } |
        ForEach-Object {
            [pscustomobject][ordered]@{
                processId = [int64]$_.OwningProcess
                LocalAddress = [string]$_.LocalAddress
                LocalPort = [int]$_.LocalPort
            }
        } | Sort-Object processId, LocalAddress, LocalPort)
    $comparisonKeys = @(
        @($tcpEndpoints | ForEach-Object {
            'tcp|{0}|{1}|{2}|{3}|{4}|{5}' -f $_.processId,
                $_.LocalAddress,
                $_.LocalPort,
                $_.RemoteAddress,
                $_.RemotePort,
                $_.State
        }) +
        @($udpEndpoints | ForEach-Object {
            'udp|{0}|{1}|{2}' -f $_.processId,
                $_.LocalAddress,
                $_.LocalPort
        }) | Sort-Object
    )

    return [pscustomobject][ordered]@{
        capturedAtUtc = [DateTime]::UtcNow.ToString('o')
        tcpEndpoints = $tcpEndpoints
        udpEndpoints = $udpEndpoints
        comparisonKeys = $comparisonKeys
    }
}

function Get-JTSCompanionProcessesForPathSet {
    param([Parameter(Mandatory)] [hashtable] $PathSet)

    return @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_.ExecutablePath) -and
        $PathSet.ContainsKey(
            ([IO.Path]::GetFullPath($_.ExecutablePath)).ToLowerInvariant())
    })
}

function Assert-JTSCompanionEndpointSet {
    param(
        [Parameter(Mandatory)] $ExpectedSnapshot,
        [Parameter(Mandatory)] $ActualSnapshot,
        [Parameter(Mandatory)] [string] $Stage,
        [Parameter(Mandatory)] [string] $Checkpoint
    )

    $expectedKeys = @($ExpectedSnapshot.comparisonKeys)
    $actualKeys = @($ActualSnapshot.comparisonKeys)
    $differences = @(if ($expectedKeys.Count -ne $actualKeys.Count) {
        [pscustomobject]@{ reason = 'endpoint-count-mismatch' }
    } elseif ($expectedKeys.Count -gt 0) {
        Compare-Object -ReferenceObject $expectedKeys -DifferenceObject $actualKeys
    })
    if ($expectedKeys.Count -ne $actualKeys.Count -or $differences.Count -ne 0) {
        throw "The monitored Companion endpoint set changed at '$Checkpoint' during '$Stage' evidence capture."
    }
}

function Get-JTSCompanionNetworkSnapshot {
    param(
        [Parameter(Mandatory)] [string] $Stage,
        [Parameter(Mandatory)] [string[]] $ExecutablePaths,
        [string[]] $ExpectedRunningPaths = @(),
        [string[]] $ExpectedAbsentPaths = @(),
        [string] $ExpectedOwnerSid
    )

    $monitoredPaths = @($ExecutablePaths |
        ForEach-Object { [IO.Path]::GetFullPath($_) } |
        Select-Object -Unique)
    $expectedRunning = @($ExpectedRunningPaths |
        ForEach-Object { [IO.Path]::GetFullPath($_) } |
        Select-Object -Unique)
    $expectedAbsent = @($ExpectedAbsentPaths |
        ForEach-Object { [IO.Path]::GetFullPath($_) } |
        Select-Object -Unique)
    $pathSet = @{}
    foreach ($path in $monitoredPaths) {
        $pathSet[$path.ToLowerInvariant()] = $true
    }
    $runningSet = @{}
    foreach ($path in $expectedRunning) {
        $key = $path.ToLowerInvariant()
        if (-not $pathSet.ContainsKey($key)) {
            throw "Expected-running path is not monitored: $path"
        }
        $runningSet[$key] = $true
    }
    $absentSet = @{}
    foreach ($path in $expectedAbsent) {
        $key = $path.ToLowerInvariant()
        if (-not $pathSet.ContainsKey($key)) {
            throw "Expected-absent path is not monitored: $path"
        }
        if ($runningSet.ContainsKey($key)) {
            throw "A process path cannot be both expected-running and expected-absent: $path"
        }
        $absentSet[$key] = $true
    }

    $processes = @(Get-JTSCompanionProcessesForPathSet -PathSet $pathSet)
    $processEvidence = New-Object Collections.Generic.List[object]
    $processCountsByPath = @{}
    foreach ($key in $pathSet.Keys) {
        $processCountsByPath[$key] = 0
    }
    foreach ($process in $processes) {
        $executablePath = [IO.Path]::GetFullPath($process.ExecutablePath)
        $pathKey = $executablePath.ToLowerInvariant()
        $processCountsByPath[$pathKey] = [int]$processCountsByPath[$pathKey] + 1
        $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop
        if ($owner.ReturnValue -ne 0 -or [string]::IsNullOrWhiteSpace($owner.Sid)) {
            throw "Could not bind process $($process.ProcessId) to a Windows owner SID."
        }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedOwnerSid) -and
            $owner.Sid -ne $ExpectedOwnerSid) {
            throw "Process $($process.ProcessId) is owned by an unexpected Windows SID."
        }
        $creationDate = [DateTime]$process.CreationDate
        # Hash the exact executable while the process identity is still live,
        # then re-read PID/path/start time after every potentially slow query.
        $executableSha256 = (Get-FileHash -Algorithm SHA256 `
            -LiteralPath $executablePath -ErrorAction Stop).Hash.ToLowerInvariant()
        $recheck = @(Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $process.ProcessId) -ErrorAction Stop)
        if ($recheck.Count -ne 1 -or
            [string]::IsNullOrWhiteSpace($recheck[0].ExecutablePath) -or
            [IO.Path]::GetFullPath($recheck[0].ExecutablePath) -ne $executablePath -or
            ([DateTime]$recheck[0].CreationDate) -ne $creationDate) {
            throw "Process $($process.ProcessId) changed identity during network evidence capture."
        }
        $processEvidence.Add([pscustomobject][ordered]@{
            processId = $process.ProcessId
            parentProcessId = $process.ParentProcessId
            name = $process.Name
            executablePath = $executablePath
            executableSha256 = $executableSha256
            ownerSid = $owner.Sid
            creationTimeUtc = $creationDate.ToUniversalTime().ToString('o')
            tcpEndpoints = @()
            udpEndpoints = @()
        })
    }

    # Re-enumerate after the owner and executable-hash work. Without this set
    # comparison, a same-image process starting during capture could be omitted.
    $finalProcesses = @(Get-JTSCompanionProcessesForPathSet -PathSet $pathSet)
    $capturedIdentityKeys = @(Get-JTSCompanionProcessIdentityKeys `
        -Processes $processEvidence.ToArray())
    Assert-JTSCompanionProcessIdentitySet `
        -ExpectedIdentityKeys $capturedIdentityKeys `
        -Processes $finalProcesses `
        -Stage $Stage `
        -Checkpoint 'after executable hashing'

    # Endpoint evidence is sampled repeatedly over a real monotonic interval
    # after the slow owner/hash work. Every endpoint query is followed by an
    # exact PID/path/start identity recheck. A separate terminal endpoint query
    # and identity recheck occur only after the minimum interval has elapsed.
    # This is bounded observation evidence, not a claim about times outside the
    # recorded window.
    $minimumEndpointStabilityMilliseconds = 2000
    $endpointSampleIntervalMilliseconds = 250
    $maximumEndpointSamples = 16
    $endpointSnapshots = New-Object Collections.Generic.List[object]
    $endpointStabilityWatch = [Diagnostics.Stopwatch]::StartNew()

    $baselineEndpointSnapshot = Get-JTSCompanionEndpointSnapshot `
        -Processes $processEvidence.ToArray()
    $endpointSnapshots.Add($baselineEndpointSnapshot)
    $processesAfterBaselineEndpoint = @(
        Get-JTSCompanionProcessesForPathSet -PathSet $pathSet)
    Assert-JTSCompanionProcessIdentitySet `
        -ExpectedIdentityKeys $capturedIdentityKeys `
        -Processes $processesAfterBaselineEndpoint `
        -Stage $Stage `
        -Checkpoint 'after endpoint stability baseline'

    while ($endpointStabilityWatch.ElapsedMilliseconds -lt
            $minimumEndpointStabilityMilliseconds) {
        if ($endpointSnapshots.Count -ge $maximumEndpointSamples) {
            throw "The endpoint stability window exceeded its bounded sample count during '$Stage'."
        }
        $remainingMilliseconds = [int64]$minimumEndpointStabilityMilliseconds -
            [int64]$endpointStabilityWatch.ElapsedMilliseconds
        $sleepMilliseconds = [int][Math]::Max(
            [int64]1,
            [Math]::Min(
                [int64]$endpointSampleIntervalMilliseconds,
                $remainingMilliseconds))
        Start-Sleep -Milliseconds $sleepMilliseconds

        $sample = Get-JTSCompanionEndpointSnapshot `
            -Processes $processEvidence.ToArray()
        $endpointSnapshots.Add($sample)
        $processesAfterSample = @(
            Get-JTSCompanionProcessesForPathSet -PathSet $pathSet)
        Assert-JTSCompanionProcessIdentitySet `
            -ExpectedIdentityKeys $capturedIdentityKeys `
            -Processes $processesAfterSample `
            -Stage $Stage `
            -Checkpoint ("after endpoint stability sample {0}" -f $endpointSnapshots.Count)
        Assert-JTSCompanionEndpointSet `
            -ExpectedSnapshot $baselineEndpointSnapshot `
            -ActualSnapshot $sample `
            -Stage $Stage `
            -Checkpoint ("endpoint stability sample {0}" -f $endpointSnapshots.Count)
    }

    $terminalEndpointSnapshot = Get-JTSCompanionEndpointSnapshot `
        -Processes $processEvidence.ToArray()
    $endpointSnapshots.Add($terminalEndpointSnapshot)
    $processesAfterTerminalEndpoint = @(
        Get-JTSCompanionProcessesForPathSet -PathSet $pathSet)
    Assert-JTSCompanionProcessIdentitySet `
        -ExpectedIdentityKeys $capturedIdentityKeys `
        -Processes $processesAfterTerminalEndpoint `
        -Stage $Stage `
        -Checkpoint 'after terminal endpoint snapshot'
    Assert-JTSCompanionEndpointSet `
        -ExpectedSnapshot $baselineEndpointSnapshot `
        -ActualSnapshot $terminalEndpointSnapshot `
        -Stage $Stage `
        -Checkpoint 'terminal endpoint snapshot'
    $endpointStabilityWatch.Stop()
    $endpointStabilityDurationMilliseconds =
        [int64]$endpointStabilityWatch.ElapsedMilliseconds
    if ($endpointStabilityDurationMilliseconds -lt
        $minimumEndpointStabilityMilliseconds) {
        throw "The endpoint stability window ended too early during '$Stage'."
    }

    foreach ($process in $processEvidence) {
        $process.tcpEndpoints = @($terminalEndpointSnapshot.tcpEndpoints |
            Where-Object { $_.processId -eq $process.processId } |
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State)
        $process.udpEndpoints = @($terminalEndpointSnapshot.udpEndpoints |
            Where-Object { $_.processId -eq $process.processId } |
            Select-Object LocalAddress, LocalPort)
    }
    $tcpCount = $terminalEndpointSnapshot.tcpEndpoints.Count
    $udpCount = $terminalEndpointSnapshot.udpEndpoints.Count

    foreach ($path in $expectedRunning) {
        $count = [int]$processCountsByPath[$path.ToLowerInvariant()]
        if ($count -ne 1) {
            throw "Expected exactly one running process at '$path' during '$Stage'; found $count."
        }
    }
    foreach ($path in $expectedAbsent) {
        $count = [int]$processCountsByPath[$path.ToLowerInvariant()]
        if ($count -ne 0) {
            throw "Expected no running process at '$path' during '$Stage'; found $count."
        }
    }

    return [pscustomobject][ordered]@{
        stage = $Stage
        capturedAtUtc = [DateTime]::UtcNow.ToString('o')
        monitoredExecutablePaths = $monitoredPaths
        expectedRunningPaths = $expectedRunning
        expectedAbsentPaths = $expectedAbsent
        expectedOwnerSid = $ExpectedOwnerSid
        processCount = $processEvidence.Count
        processCountsByPath = [pscustomobject]$processCountsByPath
        processExpectationsSatisfied = $true
        processSetRevalidated = $true
        endpointQueriesSucceeded = $true
        endpointSnapshotsStable = $true
        endpointProcessIdentityRevalidated = $true
        endpointStabilityWindowSatisfied = $true
        endpointTerminalSnapshotRevalidated = $true
        endpointRequiredStabilityMilliseconds = $minimumEndpointStabilityMilliseconds
        endpointStabilityDurationMilliseconds = $endpointStabilityDurationMilliseconds
        endpointSampleIntervalMilliseconds = $endpointSampleIntervalMilliseconds
        endpointSampleCount = $endpointSnapshots.Count
        endpointSnapshotCapturedAtUtc = @($endpointSnapshots.ToArray() |
            ForEach-Object { $_.capturedAtUtc })
        tcpEndpointCount = $tcpCount
        udpEndpointCount = $udpCount
        processes = $processEvidence.ToArray()
    }
}

function Assert-JTSCompanionOwnsNoNetworkEndpoints {
    param([Parameter(Mandatory)] $Snapshot)

    if ($Snapshot.endpointQueriesSucceeded -ne $true -or
        $Snapshot.processExpectationsSatisfied -ne $true -or
        $Snapshot.processSetRevalidated -ne $true -or
        $Snapshot.endpointSnapshotsStable -ne $true -or
        $Snapshot.endpointProcessIdentityRevalidated -ne $true -or
        $Snapshot.endpointStabilityWindowSatisfied -ne $true -or
        $Snapshot.endpointTerminalSnapshotRevalidated -ne $true -or
        [int64]$Snapshot.endpointRequiredStabilityMilliseconds -lt 2000 -or
        [int64]$Snapshot.endpointStabilityDurationMilliseconds -lt
            [int64]$Snapshot.endpointRequiredStabilityMilliseconds -or
        [int]$Snapshot.endpointSampleCount -lt 3) {
        throw "The JTS Windows Companion process/network snapshot is incomplete at stage '$($Snapshot.stage)'."
    }
    if (@($Snapshot.expectedRunningPaths).Count -gt 0 -and $Snapshot.processCount -eq 0) {
        throw "Expected JTS Windows Companion processes were absent at stage '$($Snapshot.stage)'."
    }
    if ($Snapshot.tcpEndpointCount -ne 0 -or $Snapshot.udpEndpointCount -ne 0) {
        throw "A JTS Windows Companion process owns an unexpected network endpoint at stage '$($Snapshot.stage)'."
    }
}
