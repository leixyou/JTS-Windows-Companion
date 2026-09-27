[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $TestOutputDirectory,
    [Parameter(Mandatory = $true)][string] $EvidenceDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or $env:GITHUB_ACTIONS -cne 'true') {
    throw 'This harness creates a disposable local account only on an explicitly selected Windows GitHub Actions runner.'
}
$current = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    if (-not ([Security.Principal.WindowsPrincipal]::new($current)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The CI harness requires an administrator parent; the tests run under a separate standard account.'
    }
} finally { $current.Dispose() }
$source = [IO.Path]::GetFullPath($TestOutputDirectory)
$evidence = [IO.Path]::GetFullPath($EvidenceDirectory)
$assemblyName = 'JTS.WindowsCompanion.Pairing.Tests.dll'
if (-not (Test-Path -LiteralPath (Join-Path $source $assemblyName) -PathType Leaf)) { throw 'Build the Pairing tests first.' }
if (Test-Path -LiteralPath $evidence) { throw 'Use a new evidence directory.' }
$dotnet = (Get-Command dotnet -CommandType Application).Source
$pwsh = (Get-Process -Id $PID).Path
$root = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('JTS-Identity-CI-' + [Guid]::NewGuid().ToString('N'))
$name = 'jtsci' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
$account = $null; $process = $null; $failure = $null; $cleanupErrors = [Collections.Generic.List[string]]::new()
$results = Join-Path $root 'results'

function New-TestDirectory([string] $Path, [string] $Sid, [Security.AccessControl.FileSystemRights] $Rights) {
    $directory = New-Item -ItemType Directory -Path $Path
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($entry in @(@{ Sid = 'S-1-5-18'; Rights = 'FullControl' }, @{ Sid = 'S-1-5-32-544'; Rights = 'FullControl' }, @{ Sid = $Sid; Rights = $Rights })) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($entry.Sid), [Security.AccessControl.FileSystemRights]$entry.Rights,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
    }
    [IO.FileSystemAclExtensions]::SetAccessControl([IO.DirectoryInfo]$directory, $acl)
}

try {
    # No password value, credential object, or account object is written to a log or file.
    $random = [Security.Cryptography.RandomNumberGenerator]::GetBytes(48)
    try { $password = ConvertTo-SecureString ('Aa1!' + [Convert]::ToBase64String($random)) -AsPlainText -Force }
    finally { [Array]::Clear($random) }
    $account = New-LocalUser -Name $name -Password $password -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword
    $sid = $account.SID.Value
    $validSid = $sid -cmatch '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-([0-9]+)$'
    if (-not $validSid -or [uint32]$Matches[1] -lt 1000) { throw 'The disposable account does not satisfy the production identity policy.' }
    $usersGroup = (Get-LocalGroup -SID 'S-1-5-32-545').Name
    if (@(Get-LocalGroupMember -Group $usersGroup | Where-Object { $_.SID.Value -ceq $sid }).Count -eq 0) {
        Add-LocalGroupMember -Group $usersGroup -Member $account
    }
    New-TestDirectory $root $sid ReadAndExecute
    $stage = Join-Path $root 'payload'; New-TestDirectory $stage $sid ReadAndExecute
    $identityRoot = Join-Path $root 'identity'; New-TestDirectory $identityRoot $sid FullControl
    New-TestDirectory $results $sid FullControl
    Copy-Item -Path (Join-Path $source '*') -Destination $stage -Recurse
    $childScript = Join-Path $stage 'run-native-identity-ci-child.ps1'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'run-native-identity-ci-child.ps1') -Destination $childScript
    $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $childScript, '-ExpectedSid', $sid,
        '-Dotnet', $dotnet, '-TestAssembly', (Join-Path $stage $assemblyName), '-IdentityRoot', $identityRoot, '-ResultsRoot', $results)
    # Start-Process joins ArgumentList; quote every argument and reject command-line metacharacters in paths.
    foreach ($argument in $arguments) { if ($argument.Contains('"') -or $argument.Contains("`r") -or $argument.Contains("`n")) { throw 'Invalid child process argument.' } }
    $quoted = ($arguments | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $credential = [Management.Automation.PSCredential]::new("$env:COMPUTERNAME\$name", $password)
    $process = Start-Process -FilePath $pwsh -ArgumentList $quoted -Credential $credential -LoadUserProfile -WorkingDirectory $stage -PassThru `
        -RedirectStandardOutput (Join-Path $results 'stdout.log') -RedirectStandardError (Join-Path $results 'stderr.log')
    if (-not $process.WaitForExit(180000)) { throw 'Native identity tests exceeded their CI deadline.' }
    $process.Refresh()
    if ($process.ExitCode -ne 0) { throw ('Native identity test process failed with exit code {0}.' -f $process.ExitCode) }
    $trx = Join-Path $results 'native-identity.trx'
    if (-not (Test-Path -LiteralPath $trx -PathType Leaf)) { throw 'Native identity TRX was not produced.' }
    [xml] $report = [IO.File]::ReadAllText($trx)
    $cases = @($report.SelectNodes("//*[local-name()='UnitTestResult']"))
    $expected = @('CurrentUserDpapiAndReopenedUserKeyAuthenticateTls13', 'CurrentUserDpapiAndReopenedUserKeyAuthenticateExplicitTls12',
        'ExpandedFileReadAclIsRejectedBeforeIdentityLoading', 'ReopenedIdentityAuthenticatesPinnedTlsAndRetainsPairingBinding')
    if ($cases.Count -ne 4 -or @($cases | Where-Object { $_.outcome -cne 'Passed' }).Count -ne 0) { throw 'Native identity gate requires exactly four passing tests with no skips.' }
    foreach ($test in $expected) {
        if (@($cases | Where-Object { $_.testName.EndsWith('.' + $test, [StringComparison]::Ordinal) }).Count -ne 1) { throw 'Native identity TRX does not contain the exact expected tests.' }
    }
    Write-Output 'Native identity gate: four passed, zero failed, zero skipped under a disposable standard account.'
} catch { $failure = $_ }
finally {
    if ($null -ne $process) {
        try { if (-not $process.HasExited) { $process.Kill($true); if (-not $process.WaitForExit(10000)) { throw 'Child did not stop.' } } }
        catch { $cleanupErrors.Add('Child-process cleanup failed.') }
        $process.Dispose()
    }
    try {
        New-Item -ItemType Directory -Path $evidence | Out-Null
        foreach ($file in @('stdout.log', 'stderr.log', 'native-identity.trx')) {
            $path = Join-Path $results $file
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                Copy-Item -LiteralPath $path -Destination (Join-Path $evidence $file)
                if ($file -ne 'native-identity.trx') { Get-Content -LiteralPath $path | Write-Output }
            }
        }
    } catch { $cleanupErrors.Add('Evidence preservation failed.') }
    if ($null -ne $account) {
        try {
            $profile = Get-CimInstance Win32_UserProfile -Filter ("SID='{0}'" -f $account.SID.Value)
            for ($attempt = 0; $null -ne $profile -and $profile.Loaded -and $attempt -lt 25; $attempt++) {
                Start-Sleep -Milliseconds 200
                $profile = Get-CimInstance Win32_UserProfile -Filter ("SID='{0}'" -f $account.SID.Value)
            }
            if ($null -ne $profile) {
                if ($profile.Loaded) { throw 'The disposable account profile is still loaded.' }
                $profile | Remove-CimInstance
            }
        } catch { $cleanupErrors.Add('Disposable profile cleanup failed.') }
        try { Remove-LocalUser -SID $account.SID } catch { $cleanupErrors.Add('Disposable account cleanup failed.') }
    }
    try { if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force } }
    catch { $cleanupErrors.Add('Disposable test-directory cleanup failed.') }
    if ($null -ne (Get-Variable password -ErrorAction SilentlyContinue)) { $password.Dispose() }
}
if ($cleanupErrors.Count -gt 0) { Write-Error ($cleanupErrors -join ' ') -ErrorAction Continue }
if ($null -ne $failure) { throw $failure }
if ($cleanupErrors.Count -gt 0) { throw 'Native identity cleanup was incomplete.' }
