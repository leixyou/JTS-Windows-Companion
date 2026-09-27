[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $ExpectedSid,
    [Parameter(Mandatory = $true)][string] $Dotnet,
    [Parameter(Mandatory = $true)][string] $TestAssembly,
    [Parameter(Mandatory = $true)][string] $IdentityRoot,
    [Parameter(Mandatory = $true)][string] $ResultsRoot
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# WindowsPrincipal.IsInRole duplicates this handle while checking the effective groups.
$current = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    if ($current.User.Value -cne $ExpectedSid -or $current.ImpersonationLevel -ne [Security.Principal.TokenImpersonationLevel]::None -or
        ([Security.Principal.WindowsPrincipal]::new($current)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The native identity test child must have the exact standard-account primary token.'
    }
} finally { $current.Dispose() }
$profile = [Environment]::GetFolderPath('UserProfile')
if ([string]::IsNullOrEmpty($profile) -or -not (Test-Path -LiteralPath $profile -PathType Container)) { throw 'The disposable user profile is not loaded.' }
$env:USERPROFILE = $profile
$env:APPDATA = [Environment]::GetFolderPath('ApplicationData')
$env:LOCALAPPDATA = [Environment]::GetFolderPath('LocalApplicationData')
$env:DOTNET_CLI_HOME = $profile
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:TEMP = Join-Path $ResultsRoot 'temp'; New-Item -ItemType Directory -Path $env:TEMP | Out-Null
$env:TMP = $env:TEMP
$env:JTS_IDENTITY_TEST_ACCOUNT_SID = $ExpectedSid
$env:JTS_IDENTITY_TEST_DIRECTORY = $IdentityRoot
& $Dotnet vstest $TestAssembly '--TestCaseFilter:FullyQualifiedName~WindowsIdentityAcceptanceTests|FullyQualifiedName~IdentityTransportTests' `
    '--Logger:trx;LogFileName=native-identity.trx' "--ResultsDirectory:$ResultsRoot"
exit $LASTEXITCODE
