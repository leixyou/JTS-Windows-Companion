[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $CandidatePath,
    [Parameter(Mandatory)] [string] $BuildEvidencePath,
    [Parameter(Mandatory)] [ValidatePattern('\A[0-9a-fA-F]{64}\z')] [string] $ExpectedBuildEvidenceSha256,
    [string] $EvidenceDirectory,
    [switch] $CaptureAuthenticodeDiagnostics,
    [switch] $RequireSignToolEvidence
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'The authorized-lab Setup test must run on Windows.'
}
if ($RequireSignToolEvidence) {
    throw 'Mandatory Authenticode evidence is no longer part of this diagnostic harness. Use CaptureAuthenticodeDiagnostics for optional metadata.'
}
. (Join-Path $PSScriptRoot 'windows-companion-evidence.ps1')

$CandidatePath = [IO.Path]::GetFullPath($CandidatePath)
if (-not (Test-Path -LiteralPath $CandidatePath -PathType Leaf)) {
    throw 'The authorized-lab Setup candidate is missing.'
}
if ([string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
    $EvidenceDirectory = Join-Path (Split-Path -Parent $CandidatePath) 'qa-evidence'
}
$EvidenceDirectory = [IO.Path]::GetFullPath($EvidenceDirectory)
New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null

$installRoot = Join-Path $env:LOCALAPPDATA 'Programs\JTS Terminal\Windows Companion'
$installParent = Split-Path -Parent $installRoot
$stateRoot = Join-Path $env:LOCALAPPDATA 'JTSTerminal\WindowsCompanion'
$agentPath = Join-Path $installRoot 'JTS.WindowsCompanion.Agent.exe'
$brokerPath = Join-Path $installRoot 'JTS.WindowsCompanion.UacBroker.exe'
$setupPath = Join-Path $installRoot 'JTS.WindowsCompanion.Setup.exe'
$installedManifestPath = Join-Path $installRoot 'JTS.WindowsCompanion.release.json'
$installedPaths = @($agentPath, $brokerPath, $setupPath)
$monitoredNetworkPaths = @($CandidatePath) + $installedPaths
$lockPath = Join-Path $installParent '.jts-windows-companion-setup.lock'
$journalPath = Join-Path $installParent '.jts-windows-companion-setup-transaction.json'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$runValueName = 'JTS Windows Companion'
$uninstallKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\JTSWindowsCompanion'
$temporarySetupPattern = 'JTS-Windows-Companion-Setup-*'
$cleanupScriptPattern = '.jts-setup-cleanup-*.cmd'
$baselineTemporaryRoots = @(Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -Directory `
    -Filter $temporarySetupPattern -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
$baselineCleanupScripts = @(Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -File `
    -Filter $cleanupScriptPattern -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$steps = New-Object Collections.Generic.List[object]
$networkSnapshots = New-Object Collections.Generic.List[object]

function Assert-True {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) { throw $Message }
}

function Assert-LabLocalPath {
    param([Parameter(Mandatory)] [string] $Path)
    $current = [IO.Path]::GetFullPath($Path)
    if ($current.StartsWith('\\')) { throw 'Lab artifacts must use local paths.' }
    while (-not [string]::IsNullOrEmpty($current)) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "A lab artifact path or ancestor is a reparse point: $current"
            }
        }
        $current = [IO.Path]::GetDirectoryName($current)
    }
}

function Get-LabFileSnapshot {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [long] $MaximumBytes = 536870912,
        [switch] $IncludeBytes
    )
    $fullPath = [IO.Path]::GetFullPath($Path)
    Assert-LabLocalPath -Path $fullPath
    $stream = [IO.File]::Open($fullPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        Assert-LabLocalPath -Path $fullPath
        if ($stream.Length -le 0 -or $stream.Length -gt $MaximumBytes) {
            throw 'The lab artifact has an invalid or excessive size.'
        }
        $algorithm = [Security.Cryptography.SHA256]::Create()
        try { $digest = $algorithm.ComputeHash($stream) } finally { $algorithm.Dispose() }
        $bytes = $null
        if ($IncludeBytes) {
            $bytes = [byte[]]::new([int]$stream.Length)
            $stream.Position = 0
            $offset = 0
            while ($offset -lt $bytes.Length) {
                $count = $stream.Read($bytes, $offset, $bytes.Length - $offset)
                if ($count -le 0) { throw 'The lab artifact ended before its recorded length.' }
                $offset += $count
            }
        }
        return [ordered]@{
            path = $fullPath
            sizeBytes = $stream.Length
            sha256 = [BitConverter]::ToString($digest).Replace('-', '').ToLowerInvariant()
            bytes = $bytes
        }
    } finally { $stream.Dispose() }
}

function Assert-LabArtifact {
    param([Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] $Expected)
    $snapshot = Get-LabFileSnapshot -Path $Path
    if ($snapshot.sizeBytes -ne $Expected.sizeBytes -or $snapshot.sha256 -cne $Expected.sha256) {
        throw "The artifact differs from the pre-install local build snapshot: $Path"
    }
}

function Open-ExpectedSetupImage {
    param([Parameter(Mandatory)] [string] $Path)
    Assert-LabLocalPath -Path $Path
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        Assert-LabLocalPath -Path $Path
        if ($stream.Length -ne $expectedArtifacts.setup.sizeBytes) {
            throw 'The Setup image length no longer matches the fixed candidate bytes.'
        }
        $algorithm = [Security.Cryptography.SHA256]::Create()
        try { $digest = $algorithm.ComputeHash($stream) } finally { $algorithm.Dispose() }
        $hash = [BitConverter]::ToString($digest).Replace('-', '').ToLowerInvariant()
        if ($stream.Length -ne $expectedArtifacts.setup.sizeBytes -or $hash -cne $expectedArtifacts.setup.sha256) {
            throw 'The Setup image no longer matches the fixed candidate bytes.'
        }
        return $stream
    } catch { $stream.Dispose(); throw }
}

function Get-TrustedLabBuildSnapshot {
    # The caller pins this digest immediately after its own local builder succeeds.
    # Adjacent .sha256 files or a key supplied by an installed image are not anchors.
    $record = Get-LabFileSnapshot -Path $BuildEvidencePath -MaximumBytes 16384 -IncludeBytes
    if ($record.sha256 -cne $ExpectedBuildEvidenceSha256.ToLowerInvariant()) {
        throw 'The local diagnostic build evidence does not match its pre-recorded SHA-256.'
    }
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $build = $utf8.GetString($record.bytes) | ConvertFrom-Json -ErrorAction Stop
    if (($build.schemaVersion -isnot [int] -and $build.schemaVersion -isnot [long]) -or
        $build.schemaVersion -ne 1 -or $build.evidenceKind -cne 'authorized-lab-diagnostic-build' -or
        $build.releaseId -notmatch '\Aauthorized-lab-[0-9a-f]{32}\z' -or
        $build.productionIdentity -isnot [bool] -or $build.productionIdentity -ne $false -or
        $build.authenticodeRequired -isnot [bool] -or $build.authenticodeRequired -ne $false -or
        @($build.files).Count -ne 5) {
        throw 'The pinned build evidence is not a nonproduction diagnostic build.'
    }
    $buildRoot = Split-Path -Parent $record.path
    $pathsByRole = [ordered]@{
        agent = 'payloads/JTS.WindowsCompanion.Agent.exe'
        broker = 'payloads/JTS.WindowsCompanion.UacBroker.exe'
        setup = 'JTS-Windows-Companion-2.0.0-win-x64-AUTHORIZED-LAB-ONLY.exe'
        'release-manifest' = 'JTS.WindowsCompanion.release.json'
        'release-public-key' = 'JTS.WindowsCompanion.release-public.pem'
    }
    $expected = @{}
    foreach ($file in $build.files) {
        $role = [string]$file.role
        if (-not $pathsByRole.Contains($role) -or $expected.ContainsKey($role) -or
            [string]$file.relativePath -cne $pathsByRole[$role] -or
            [string]$file.fileName -cne [IO.Path]::GetFileName($pathsByRole[$role]) -or
            $file.sha256 -isnot [string] -or $file.sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or
            ($file.sizeBytes -isnot [int] -and $file.sizeBytes -isnot [long]) -or
            $file.sizeBytes -le 0 -or $file.sizeBytes -gt 536870912) {
            throw 'The diagnostic artifact inventory has a duplicate, malformed, or unexpected entry.'
        }
        $artifactPath = [IO.Path]::GetFullPath((Join-Path $buildRoot $pathsByRole[$role]))
        Assert-LabArtifact -Path $artifactPath -Expected $file
        $expected[$role] = [ordered]@{
            path = $artifactPath; sizeBytes = [long]$file.sizeBytes; sha256 = [string]$file.sha256
        }
    }
    if ($CandidatePath -ine $expected.setup.path) { throw 'CandidatePath is not the exact pinned local build output.' }
    $manifest = Get-LabFileSnapshot -Path $expected['release-manifest'].path -MaximumBytes 65536 -IncludeBytes
    if ($manifest.sha256 -cne $expected['release-manifest'].sha256) { throw 'The release manifest changed before parsing.' }
    $publicKey = Get-LabFileSnapshot -Path $expected['release-public-key'].path -MaximumBytes 4096
    if ($publicKey.sha256 -cne $expected['release-public-key'].sha256) { throw 'The diagnostic public key changed.' }
    $envelope = $utf8.GetString($manifest.bytes) | ConvertFrom-Json -ErrorAction Stop
    $payloadBytes = [Convert]::FromBase64String([string]$envelope.payload)
    $payload = $utf8.GetString($payloadBytes) | ConvertFrom-Json -ErrorAction Stop
    if (($payload.schemaVersion -isnot [int] -and $payload.schemaVersion -isnot [long]) -or
        $payload.schemaVersion -ne 1 -or [string]$payload.releaseId -cne [string]$build.releaseId -or
        @($payload.files).Count -ne 2) {
        throw 'The exact project-signed payload is detached from this diagnostic build.'
    }
    foreach ($role in @('agent', 'broker')) {
        $entries = @($payload.files | Where-Object {
            [string]$_.fileName -ceq [IO.Path]::GetFileName($expected[$role].path)
        })
        if ($entries.Count -ne 1 -or [string]$entries[0].sha256 -cne $expected[$role].sha256) {
            throw 'The signed Agent/Broker hashes differ from the pinned local build snapshot.'
        }
    }
    # Cryptographic verification remains in Setup/Agent/Broker's compiled Core key.
    # This PS 5-compatible harness checks exact known-builder bytes, not a new key policy.
    return [ordered]@{ buildEvidence = $record; releaseId = $build.releaseId; artifacts = $expected }
}

function Add-Step {
    param([string] $Name, [hashtable] $Data = @{})
    $record = [ordered]@{ name = $Name; passed = $true; atUtc = [DateTime]::UtcNow.ToString('o') }
    foreach ($entry in $Data.GetEnumerator()) { $record[$entry.Key] = $entry.Value }
    $steps.Add([pscustomobject]$record)
}

function Add-NetworkSnapshot {
    param(
        [Parameter(Mandatory)] [string] $Stage,
        [string[]] $ExpectedRunningPaths = @(),
        [string[]] $ExpectedAbsentPaths = @(),
        [string[]] $AdditionalExecutablePaths = @()
    )

    $snapshot = Get-JTSCompanionNetworkSnapshot `
        -Stage $Stage `
        -ExecutablePaths (@($monitoredNetworkPaths) + @($AdditionalExecutablePaths)) `
        -ExpectedRunningPaths $ExpectedRunningPaths `
        -ExpectedAbsentPaths $ExpectedAbsentPaths `
        -ExpectedOwnerSid $currentSid
    Assert-JTSCompanionOwnsNoNetworkEndpoints -Snapshot $snapshot
    $networkSnapshots.Add($snapshot)
}

function Invoke-Setup {
    param(
        [string[]] $Arguments,
        [int] $ExpectedExitCode = 0,
        [string] $Executable = $CandidatePath
    )
    $imageLock = Open-ExpectedSetupImage -Path $Executable
    try {
        $process = Start-Process -FilePath $Executable -ArgumentList $Arguments -PassThru -WindowStyle Hidden
    } finally {
        # The loader has acquired the image; release before repair/uninstall renames it.
        $imageLock.Dispose()
    }
    try {
        # Start-Process -Wait follows descendants on Windows. Setup can launch the
        # long-running Agent, so wait only for this Setup process handle instead.
        $process.WaitForExit()
        $process.Refresh()
        $actualExitCode = $process.ExitCode
    } finally {
        $process.Dispose()
    }
    if ($actualExitCode -ne $ExpectedExitCode) {
        throw "Setup exited with $actualExitCode; expected $ExpectedExitCode. Arguments: $($Arguments -join ' ')"
    }
}

function Wait-Until {
    param([scriptblock] $Condition, [int] $TimeoutSeconds, [string] $FailureMessage)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (& $Condition) { return }
        Start-Sleep -Milliseconds 50
    }
    throw $FailureMessage
}

function Get-RunValue {
    try {
        return Get-ItemPropertyValue -LiteralPath $runKey -Name $runValueName -ErrorAction Stop
    } catch {
        return $null
    }
}

function Get-InstalledAgentProcesses {
    return @(Get-CimInstance Win32_Process -Filter "Name='JTS.WindowsCompanion.Agent.exe'" |
        Where-Object { $_.ExecutablePath -eq $agentPath })
}

function Assert-NoTransactionResidue {
    Assert-True (-not (Test-Path -LiteralPath $journalPath)) 'The setup transaction journal remains.'
    $staging = @(Get-ChildItem -LiteralPath $installParent -Directory -Filter '.setup-*' -ErrorAction SilentlyContinue)
    $backup = @(Get-ChildItem -LiteralPath $installParent -Directory -Filter '.backup-*' -ErrorAction SilentlyContinue)
    Assert-True ($staging.Count -eq 0) 'A setup staging directory remains.'
    Assert-True ($backup.Count -eq 0) 'A setup backup directory remains.'
}

function Assert-InstalledState {
    param([Parameter(Mandatory)] [string] $Stage)

    Assert-LabArtifact -Path $agentPath -Expected $expectedArtifacts.agent
    Assert-LabArtifact -Path $brokerPath -Expected $expectedArtifacts.broker
    Assert-LabArtifact -Path $setupPath -Expected $expectedArtifacts.setup
    Assert-LabArtifact -Path $installedManifestPath -Expected $expectedArtifacts['release-manifest']
    Assert-True (Test-Path -LiteralPath $lockPath -PathType Leaf) 'The persistent setup lock file is missing.'
    Assert-True ((Get-Item -LiteralPath $lockPath).Length -eq 0) 'The setup lock file is not empty.'
    Assert-True (-not [string]::IsNullOrWhiteSpace((Get-RunValue))) 'The HKCU startup value is missing.'
    Assert-True (Test-Path -LiteralPath $uninstallKey) 'The HKCU uninstall key is missing.'
    Assert-True ((Get-ItemPropertyValue -LiteralPath $uninstallKey -Name InstallLocation) -eq $installRoot) `
        'The HKCU uninstall InstallLocation is incorrect.'
    Assert-NoTransactionResidue

    Wait-Until -TimeoutSeconds 15 -FailureMessage 'The installed Agent did not remain running.' -Condition {
        (Get-InstalledAgentProcesses).Count -eq 1
    }
    $agent = (Get-InstalledAgentProcesses)[0]
    $owner = Invoke-CimMethod -InputObject $agent -MethodName GetOwnerSid
    Assert-True ($owner.Sid -eq $currentSid) 'The installed Agent is not owned by the current Windows SID.'
    Add-NetworkSnapshot `
        -Stage $Stage `
        -ExpectedRunningPaths @($agentPath) `
        -ExpectedAbsentPaths @($CandidatePath, $brokerPath, $setupPath)
}

function Capture-DetachedSetupNetworkSnapshot {
    param([Parameter(Mandatory)] [string] $Stage)

    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    do {
        $temporaryProcesses = @(Get-CimInstance Win32_Process -Filter "Name='JTS.WindowsCompanion.Setup.exe'" |
            Where-Object {
                $candidatePath = $_.ExecutablePath
                -not [string]::IsNullOrWhiteSpace($candidatePath) -and
                    $candidatePath -like "*$temporarySetupPattern*" -and
                    @($baselineTemporaryRoots | Where-Object {
                        $candidatePath.StartsWith($_, [StringComparison]::OrdinalIgnoreCase)
                    }).Count -eq 0
            })
        if ($temporaryProcesses.Count -gt 1) {
            throw 'More than one detached Setup process appeared during network evidence capture.'
        }
        if ($temporaryProcesses.Count -eq 1) {
            $temporaryPath = [IO.Path]::GetFullPath($temporaryProcesses[0].ExecutablePath)
            $temporaryRoot = [IO.Path]::GetFullPath((Split-Path -Parent $temporaryPath))
            $temporaryParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
            $temporaryRootName = Split-Path -Leaf $temporaryRoot
            $ownershipMarker = Join-Path $temporaryRoot '.jts-temporary-setup-v1'
            if ([IO.Path]::GetFullPath((Split-Path -Parent $temporaryRoot)) -ne
                    $temporaryParent.TrimEnd([IO.Path]::DirectorySeparatorChar) -or
                $temporaryRootName -notmatch '\AJTS-Windows-Companion-Setup-[0-9a-fA-F]{32}\z' -or
                -not (Test-Path -LiteralPath $ownershipMarker -PathType Leaf) -or
                [IO.File]::ReadAllText($ownershipMarker) -ne
                    "JTS Windows Companion temporary setup v1`n") {
                throw 'The detached Setup process is not inside one product-owned temporary root.'
            }
            Assert-LabArtifact -Path $temporaryPath -Expected $expectedArtifacts.setup
            Assert-LabArtifact -Path $setupPath -Expected $expectedArtifacts.setup
            Add-NetworkSnapshot `
                -Stage $Stage `
                -ExpectedRunningPaths @($temporaryPath) `
                -ExpectedAbsentPaths @($CandidatePath, $brokerPath, $setupPath) `
                -AdditionalExecutablePaths @($temporaryPath)
            return
        }
        Start-Sleep -Milliseconds 5
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'The detached Setup process was never observed while it was active.'
}

function Wait-ForDetachedSetupCleanup {
    Wait-Until -TimeoutSeconds 45 -FailureMessage 'The detached Setup operation or temporary cleanup did not finish.' -Condition {
        $temporaryRoots = @(Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -Directory `
            -Filter $temporarySetupPattern -ErrorAction SilentlyContinue |
            Where-Object { $baselineTemporaryRoots -notcontains $_.FullName })
        $temporaryProcesses = @(Get-CimInstance Win32_Process -Filter "Name='JTS.WindowsCompanion.Setup.exe'" |
            Where-Object { $_.ExecutablePath -like "*$temporarySetupPattern*" })
        $cleanupScripts = @(Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -File `
            -Filter $cleanupScriptPattern -ErrorAction SilentlyContinue |
            Where-Object { $baselineCleanupScripts -notcontains $_.FullName })
        $temporaryRoots.Count -eq 0 -and $temporaryProcesses.Count -eq 0 -and $cleanupScripts.Count -eq 0 -and
            -not (Test-Path -LiteralPath $journalPath)
    }
}

function Start-SetupAndKillAtPhase {
    param(
        [string] $Phase,
        [string[]] $Arguments = @('--repair', '--quiet'),
        [scriptblock] $AdditionalCondition = { $true }
    )
    $phaseCodes = @{
        Prepared = 0
        OldInstallationMoved = 1
        NewInstallationActivated = 2
        RollbackStarted = 3
        FilesRolledBack = 4
        Committed = 5
    }
    if (-not $phaseCodes.ContainsKey($Phase)) { throw "Unknown setup phase: $Phase" }
    $process = Start-Process -FilePath $CandidatePath -ArgumentList $Arguments `
        -PassThru -WindowStyle Hidden
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    while ([DateTime]::UtcNow -lt $deadline) {
        $process.Refresh()
        if ($process.HasExited) { throw "Setup exited before phase $Phase could be terminated." }
        if (Test-Path -LiteralPath $journalPath) {
            $journal = $null
            try {
                $journal = Get-Content -LiteralPath $journalPath -Raw | ConvertFrom-Json
            } catch {
                # The journal is atomically replaced; retry if the read crossed a replacement.
            }
            if ($null -ne $journal -and [int]$journal.Phase -eq $phaseCodes[$Phase] -and
                (& $AdditionalCondition)) {
                Add-NetworkSnapshot `
                    -Stage ("active-candidate-setup-{0}" -f $Phase.ToLowerInvariant()) `
                    -ExpectedRunningPaths @($CandidatePath) `
                    -ExpectedAbsentPaths @($brokerPath, $setupPath)
                Stop-Process -Id $process.Id -Force
                $process.WaitForExit()
                return $journal.TransactionId
            }
        }
        Start-Sleep -Milliseconds 2
    }
    try { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue } catch {}
    throw "Timed out waiting to terminate Setup at phase $Phase."
}

$trustedBuild = Get-TrustedLabBuildSnapshot
$expectedArtifacts = $trustedBuild.artifacts
if ($CandidatePath.StartsWith($installRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
    $CandidatePath.StartsWith($stateRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Keep the fixed local candidate outside the installation and state trees exercised by this test.'
}
# This lease spans every direct candidate launch, including crash/recovery paths.
$candidateLease = Open-ExpectedSetupImage -Path $CandidatePath

try {
    # Begin from a clean Companion state. This intentionally purges only the test product's user-scoped state.
    Invoke-Setup -Arguments @('--uninstall-internal', '--quiet', '--purge-data')
    Add-NetworkSnapshot -Stage 'clean-start' -ExpectedAbsentPaths $monitoredNetworkPaths
    Add-Step -Name 'clean-start'

    Invoke-Setup -Arguments @('--install', '--quiet')
    Assert-InstalledState -Stage 'clean-install'
    Add-Step -Name 'clean-install' -Data @{ setupSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $setupPath).Hash.ToLowerInvariant() }

    # Reproduce residue left when a process dies before its durable journal is published.
    $orphanStaging = Join-Path $installParent ('.setup-{0}' -f [Guid]::NewGuid().ToString('N'))
    $orphanJournalTemporary = Join-Path $installParent ('.journal-{0}.tmp' -f [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $orphanStaging | Out-Null
    Set-Content -LiteralPath (Join-Path $orphanStaging 'partial-payload.bin') -Value 'partial' -NoNewline
    Set-Content -LiteralPath $orphanJournalTemporary -Value 'partial' -NoNewline
    Invoke-Setup -Arguments @('--repair', '--quiet')
    Assert-True (-not (Test-Path -LiteralPath $orphanStaging)) 'Pre-journal staging residue was not scavenged.'
    Assert-True (-not (Test-Path -LiteralPath $orphanJournalTemporary)) 'Journal publish residue was not scavenged.'
    Assert-InstalledState -Stage 'pre-journal-residue-scavenged'
    Add-Step -Name 'pre-journal-residue-scavenged'

    # A second process must fail before mutation while another session-equivalent file lease is held.
    $heldLock = [IO.File]::Open($lockPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        Invoke-Setup -Arguments @('--repair', '--quiet') -ExpectedExitCode 3
    } finally {
        $heldLock.Dispose()
    }
    Assert-InstalledState -Stage 'cross-session-lock-contention'
    Add-Step -Name 'cross-session-lock-contention'

    # Exercise the real installed-Setup detach path and its self-cleaning temporary root.
    $detachedNetworkLoad = Join-Path $installRoot 'lab-detached-network-load'
    New-Item -ItemType Directory -Path $detachedNetworkLoad -Force | Out-Null
    for ($index = 0; $index -lt 4000; $index++) {
        [IO.File]::WriteAllText((Join-Path $detachedNetworkLoad ("f{0:D5}.tmp" -f $index)), 'x')
    }
    Invoke-Setup -Executable $setupPath -Arguments @('--repair', '--quiet')
    Capture-DetachedSetupNetworkSnapshot -Stage 'installed-repair-detached-setup-active'
    Wait-ForDetachedSetupCleanup
    Assert-InstalledState -Stage 'installed-repair-detach-and-cleanup'
    Add-Step -Name 'installed-repair-detach-and-cleanup'

    # Force termination after activation and registration replacement, then observe exact old HKCU restoration.
    $registrationMarker = 'JTS-LAB-ROLLBACK-MARKER'
    Set-ItemProperty -LiteralPath $runKey -Name $runValueName -Value $registrationMarker
    $snapshotSubKey = Join-Path $uninstallKey 'LabSnapshot'
    New-Item -Path $snapshotSubKey -Force | Out-Null
    New-ItemProperty -Path $snapshotSubKey -Name 'Marker' -Value $registrationMarker `
        -PropertyType String -Force | Out-Null
    $killedTransaction = Start-SetupAndKillAtPhase -Phase 'NewInstallationActivated' -AdditionalCondition {
        (Get-RunValue) -ne $registrationMarker -and -not (Test-Path -LiteralPath $snapshotSubKey)
    }
    Assert-True (Test-Path -LiteralPath $journalPath) 'The forced activation crash did not leave its recovery journal.'

    $recoveryProcess = Start-Process -FilePath $CandidatePath -ArgumentList @('--repair', '--quiet') `
        -PassThru -WindowStyle Hidden
    $sawRunMarker = $false
    $sawTreeMarker = $false
    while (-not $recoveryProcess.HasExited) {
        if ((Get-RunValue) -eq $registrationMarker) { $sawRunMarker = $true }
        if (Test-Path -LiteralPath $snapshotSubKey) {
            try {
                if ((Get-ItemPropertyValue -LiteralPath $snapshotSubKey -Name Marker) -eq $registrationMarker) {
                    $sawTreeMarker = $true
                }
            } catch {}
        }
        Start-Sleep -Milliseconds 2
        $recoveryProcess.Refresh()
    }
    Assert-True ($recoveryProcess.ExitCode -eq 0) 'Setup failed while resuming the activation crash.'
    Assert-True ($sawRunMarker -and $sawTreeMarker) 'Exact HKCU snapshot restoration was not observed during recovery.'
    Assert-InstalledState -Stage 'forced-activation-crash-recovery'
    Assert-True ((Get-RunValue) -ne $registrationMarker) 'The successful repair retained the rollback marker.'
    Assert-True (-not (Test-Path -LiteralPath $snapshotSubKey)) 'The successful repair retained a stale uninstall subkey.'
    Add-Step -Name 'forced-activation-crash-recovery' -Data @{ transactionId = $killedTransaction; exactHkcuRestoreObserved = $true }

    # Slow committed backup cleanup with owned filler files, kill at Committed, then resume cleanup.
    $bulkRoot = Join-Path $installRoot 'lab-committed-cleanup-load'
    New-Item -ItemType Directory -Path $bulkRoot -Force | Out-Null
    for ($index = 0; $index -lt 12000; $index++) {
        [IO.File]::WriteAllText((Join-Path $bulkRoot ("f{0:D5}.tmp" -f $index)), 'x')
    }
    $committedTransaction = Start-SetupAndKillAtPhase -Phase 'Committed'
    Assert-True (Test-Path -LiteralPath $journalPath) 'The forced committed crash did not leave its cleanup journal.'
    Invoke-Setup -Arguments @('--repair', '--quiet')
    Assert-InstalledState -Stage 'forced-committed-cleanup-recovery'
    Add-Step -Name 'forced-committed-cleanup-recovery' -Data @{ transactionId = $committedTransaction }

    # Normal uninstall preserves state and uses the detached Setup cleanup path.
    New-Item -ItemType Directory -Path $stateRoot -Force | Out-Null
    $preserveMarker = Join-Path $stateRoot 'lab-preserve.marker'
    [IO.File]::WriteAllText($preserveMarker, 'preserve')
    Invoke-Setup -Executable $setupPath -Arguments @('--uninstall', '--quiet')
    Wait-Until -TimeoutSeconds 45 -FailureMessage 'Normal uninstall did not finish.' -Condition {
        -not (Test-Path -LiteralPath $installRoot) -and -not (Test-Path -LiteralPath $uninstallKey)
    }
    Wait-ForDetachedSetupCleanup
    Assert-True (Test-Path -LiteralPath $preserveMarker) 'Normal uninstall removed preserved Companion state.'
    Assert-True ((Get-InstalledAgentProcesses).Count -eq 0) 'The Agent remains after uninstall.'
    Assert-NoTransactionResidue
    Add-NetworkSnapshot `
        -Stage 'normal-uninstall-preserves-state' `
        -ExpectedAbsentPaths $monitoredNetworkPaths
    Add-Step -Name 'normal-uninstall-preserves-state'

    Invoke-Setup -Arguments @('--install', '--quiet')
    Assert-InstalledState -Stage 'pre-purge-crash-installed'
    $purgeCrashRoot = Join-Path $stateRoot 'lab-purge-crash-load'
    New-Item -ItemType Directory -Path $purgeCrashRoot -Force | Out-Null
    for ($index = 0; $index -lt 8000; $index++) {
        [IO.File]::WriteAllText((Join-Path $purgeCrashRoot ("f{0:D5}.tmp" -f $index)), 'x')
    }
    $purgeTransaction = Start-SetupAndKillAtPhase `
        -Phase 'Committed' `
        -Arguments @('--uninstall-internal', '--quiet', '--purge-data') `
        -AdditionalCondition { Test-Path -LiteralPath $stateRoot }
    Assert-True (Test-Path -LiteralPath $journalPath) 'The forced purge crash did not retain its committed journal.'
    Invoke-Setup -Arguments @('--uninstall-internal', '--quiet', '--purge-data')
    Assert-True (-not (Test-Path -LiteralPath $stateRoot)) 'Committed purge intent was not replayed after termination.'
    Assert-True (-not (Test-Path -LiteralPath $installRoot)) 'The recovered purge uninstall left the installation directory.'
    Assert-NoTransactionResidue
    Add-NetworkSnapshot `
        -Stage 'forced-purge-commit-recovery' `
        -ExpectedAbsentPaths $monitoredNetworkPaths
    Add-Step -Name 'forced-purge-commit-recovery' -Data @{ transactionId = $purgeTransaction }

    Invoke-Setup -Arguments @('--install', '--quiet')
    Assert-InstalledState -Stage 'pre-purge-uninstall-installed'
    New-Item -ItemType Directory -Path $stateRoot -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $stateRoot 'lab-purge.marker'), 'purge')
    Invoke-Setup -Executable $setupPath -Arguments @('--uninstall', '--quiet', '--purge-data')
    Wait-Until -TimeoutSeconds 45 -FailureMessage 'Purge uninstall did not finish.' -Condition {
        -not (Test-Path -LiteralPath $installRoot) -and -not (Test-Path -LiteralPath $stateRoot)
    }
    Wait-ForDetachedSetupCleanup
    Assert-NoTransactionResidue
    Add-NetworkSnapshot `
        -Stage 'purge-uninstall-removes-state' `
        -ExpectedAbsentPaths $monitoredNetworkPaths
    Add-Step -Name 'purge-uninstall-removes-state'

    # Leave the authorized machine ready for JTS Terminal 2.0 RDP MCP testing.
    Invoke-Setup -Arguments @('--install', '--quiet')
    Assert-InstalledState -Stage 'final-installed-and-user-scoped'

    $jtsServices = @(Get-Service -ErrorAction Stop |
        Where-Object { $_.Name -like '*JTS*' -or $_.DisplayName -like '*JTS*' })
    $hklmUninstallKeys = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\JTSWindowsCompanion',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\JTSWindowsCompanion'
    )
    $presentHklmUninstallKeys = @($hklmUninstallKeys | Where-Object {
        Test-Path -LiteralPath $_ -ErrorAction Stop
    })
    $firewallRules = @(Get-NetFirewallRule -ErrorAction Stop |
        Where-Object { $_.DisplayName -like '*JTS*Windows*Companion*' })
    Assert-True ($jtsServices.Count -eq 0) 'A JTS Windows service was installed unexpectedly.'
    Assert-True ($presentHklmUninstallKeys.Count -eq 0) `
        'A machine-wide JTS uninstall key was installed unexpectedly.'
    Assert-True ($firewallRules.Count -eq 0) 'A JTS Windows Companion firewall rule was installed unexpectedly.'
    Add-Step -Name 'final-installed-and-user-scoped' -Data @{
        agentProcessId = (Get-InstalledAgentProcesses)[0].ProcessId
        serviceCount = $jtsServices.Count
        firewallRuleCount = $firewallRules.Count
        presentHklmRegistrations = $presentHklmUninstallKeys
    }

    $signatureFiles = @(
        [pscustomobject]@{ role = 'candidate-setup'; path = $CandidatePath }
        [pscustomobject]@{ role = 'installed-agent'; path = $agentPath }
        [pscustomobject]@{ role = 'installed-uac-broker'; path = $brokerPath }
        [pscustomobject]@{ role = 'installed-setup'; path = $setupPath }
    )
    $authenticodeEvidence = @()
    if ($CaptureAuthenticodeDiagnostics) {
        $authenticodeEvidence = @($signatureFiles | ForEach-Object {
            $diagnosticFile = $_
            try {
                Get-JTSAuthenticodeEvidence -Role $diagnosticFile.role -Path $diagnosticFile.path
            } catch {
                [pscustomobject]@{
                    role = $diagnosticFile.role; path = $diagnosticFile.path
                    diagnosticError = $_.Exception.Message
                }
            }
        })
    }
    # Optional metadata cannot turn changed runtime bytes into passing evidence.
    Assert-LabArtifact -Path $CandidatePath -Expected $expectedArtifacts.setup
    Assert-LabArtifact -Path $agentPath -Expected $expectedArtifacts.agent
    Assert-LabArtifact -Path $brokerPath -Expected $expectedArtifacts.broker
    Assert-LabArtifact -Path $setupPath -Expected $expectedArtifacts.setup
    Assert-LabArtifact -Path $installedManifestPath -Expected $expectedArtifacts['release-manifest']
    Assert-LabArtifact -Path $BuildEvidencePath -Expected $trustedBuild.buildEvidence
    foreach ($artifact in $expectedArtifacts.Values) {
        Assert-LabArtifact -Path $artifact.path -Expected $artifact
    }

    $evidence = [ordered]@{
        schemaVersion = 2
        evidenceKind = 'authorized-lab-diagnostic-setup-qa'
        productionIdentity = $false
        authenticodeRequired = $false
        warning = 'AUTHORIZED LAB ONLY - NOT FOR DISTRIBUTION OR PRODUCTION IDENTITY EVIDENCE'
        completedAtUtc = [DateTime]::UtcNow.ToString('o')
        computerName = $env:COMPUTERNAME
        currentUserSid = $currentSid
        windows = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber)
        powershellVersion = $PSVersionTable.PSVersion.ToString()
        authenticodeDiagnosticsCaptured = $CaptureAuthenticodeDiagnostics.IsPresent
        preexistingTemporarySetupRootCount = $baselineTemporaryRoots.Count
        preexistingCleanupScriptCount = $baselineCleanupScripts.Count
        candidate = [ordered]@{
            path = $CandidatePath
            sha256 = $expectedArtifacts.setup.sha256
            sizeBytes = $expectedArtifacts.setup.sizeBytes
        }
        trustedLocalBuild = [ordered]@{
            evidencePath = $trustedBuild.buildEvidence.path
            evidenceSha256 = $trustedBuild.buildEvidence.sha256
            evidenceSizeBytes = $trustedBuild.buildEvidence.sizeBytes
            releaseId = $trustedBuild.releaseId
            artifacts = $expectedArtifacts
            allArtifactsMatchedBeforeFirstInstall = $true
            allArtifactsMatchedAfterLifecycle = $true
        }
        authenticodeEvidence = $authenticodeEvidence
        networkSnapshots = $networkSnapshots.ToArray()
        steps = $steps
    }
    $evidencePath = Join-Path $EvidenceDirectory 'authorized-lab-setup-qa.json'
    $evidence | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $evidencePath -Encoding UTF8
    Write-Host "Diagnostic authorized-lab Setup QA passed (NOT FOR DISTRIBUTION): $evidencePath"
} finally {
    $candidateLease.Dispose()
}
