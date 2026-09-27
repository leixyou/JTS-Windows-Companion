Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path -Parent $PSScriptRoot) 'Connect-RelayWindows.ps1'
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$null, [ref]$null)
foreach ($name in @('Get-JTSConnectionPackagePlan', 'Assert-JTSConnectionIdentity')) {
    $definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name }, $true)
    if ($null -eq $definition) { throw ('Connection helper missing: ' + $name) }
    # Load only pure helpers; platform checks and installer execution are never evaluated by this regression test.
    . ([scriptblock]::Create($definition.Extent.Text))
}
foreach ($system in @($false, $true)) {
    foreach ($admin in @($false, $true)) {
        foreach ($relayOnly in @($false, $true)) {
            $rejected = $false
            try { Assert-JTSConnectionIdentity -IsSystem $system -IsAdministrator $admin -RelayOnly:$relayOnly }
            catch { $rejected = $true }
            $expectedReject = $system -or ($admin -and -not $relayOnly)
            if ($rejected -ne $expectedReject) { throw 'Identity boundary changed: SYSTEM always rejected; elevated interactive users are allowed only in RelayOnly mode.' }
        }
    }
}
$root = Join-Path ([IO.Path]::GetTempPath()) ('jts connection package ' + [Guid]::NewGuid().ToString('N'))
try {
    foreach ($role in @('current-user', 'independent')) {
        $directory = New-Item -ItemType Directory -Path (Join-Path $root $role)
        [IO.File]::WriteAllText((Join-Path $directory.FullName 'JTS.WindowsCompanion.Setup.exe'), 'test fixture only')
    }
    $manifest = [pscustomobject]@{ currentUserSha256 = 'current-hash'; independentSha256 = 'relay-hash' }
    $both = @(Get-JTSConnectionPackagePlan -PackageRoot $root -Manifest $manifest)
    if ($both.Count -ne 2 -or $both[0].Role -cne 'current-user' -or $both[1].Role -cne 'independent') { throw 'Default installation order changed.' }
    if ($both[0].Hash -cne 'current-hash' -or $both[1].Hash -cne 'relay-hash') { throw 'Installer hash roles were mixed.' }
    foreach ($step in $both) { if (-not (Test-Path -LiteralPath $step.Path -PathType Leaf)) { throw 'The package plan does not resolve its nested installer.' } }
    Remove-Item -LiteralPath (Join-Path $root 'current-user') -Recurse
    $relay = @(Get-JTSConnectionPackagePlan -PackageRoot $root -Manifest ([pscustomobject]@{ independentSha256 = 'relay-only-hash' }) -RelayOnly)
    if ($relay.Count -ne 1 -or $relay[0].Role -cne 'independent' -or $relay[0].Hash -cne 'relay-only-hash' -or
        -not (Test-Path -LiteralPath $relay[0].Path -PathType Leaf)) { throw 'Relay-only bootstrap must work without any current-user installer or hash.' }
    Write-Output 'PASS connection package: nested paths with spaces, default order/hash binding, relay-only without current-user files, SYSTEM/elevated identity boundaries.'
} finally { if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force } }
