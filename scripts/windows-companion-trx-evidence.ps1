Set-StrictMode -Version Latest

function Get-JTSSha256Hex {
    param([Parameter(Mandatory)] [byte[]] $Bytes)

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha256.ComputeHash($Bytes)
    } finally {
        $sha256.Dispose()
    }
    return ([BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
}

function Get-JTSSingleReadFileBytes {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Description,
        [Parameter(Mandatory)] [int64] $MaximumLengthBytes
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $file = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "The $Description must not be a reparse point."
    }
    if ($file.Length -le 0 -or $file.Length -gt $MaximumLengthBytes) {
        throw "The $Description size is invalid."
    }
    $bytes = [IO.File]::ReadAllBytes($fullPath)
    if ($bytes.LongLength -ne $file.Length) {
        throw "The $Description changed while it was being read."
    }
    return [pscustomobject][ordered]@{
        path = $fullPath
        bytes = $bytes
        sha256 = Get-JTSSha256Hex -Bytes $bytes
    }
}

function Assert-JTSExactJsonProperties {
    param(
        [Parameter(Mandatory)] $Value,
        [Parameter(Mandatory)] [string[]] $ExpectedNames,
        [Parameter(Mandatory)] [string] $Description
    )

    if ($null -eq $Value -or $null -eq $Value.PSObject) {
        throw "The $Description is missing."
    }
    $actualNames = @($Value.PSObject.Properties.Name)
    $missing = @($ExpectedNames | Where-Object { $_ -notin $actualNames })
    $unexpected = @($actualNames | Where-Object { $_ -notin $ExpectedNames })
    if ($actualNames.Count -ne $ExpectedNames.Count -or
        $missing.Count -ne 0 -or $unexpected.Count -ne 0) {
        throw "The $Description has missing or unexpected properties."
    }
}

function Get-JTSCanonicalMethodCaseInventory {
    param([Parameter(Mandatory)] $MethodCaseCounts)

    $lines = New-Object Collections.Generic.List[string]
    foreach ($entry in $MethodCaseCounts.GetEnumerator()) {
        $lines.Add(("{0}`t{1}" -f [string]$entry.Key, [int]$entry.Value))
    }
    $sortedLines = $lines.ToArray()
    [Array]::Sort($sortedLines, [StringComparer]::Ordinal)
    return ([string]::Join("`n", $sortedLines) + "`n")
}

function Get-JTSReleaseTestInventory {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $ExpectedProjectPath
    )

    $input = Get-JTSSingleReadFileBytes `
        -Path $Path `
        -Description 'Windows Companion release-test inventory' `
        -MaximumLengthBytes 2MB
    try {
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $json = $utf8.GetString($input.bytes)
        $document = ConvertFrom-Json -InputObject $json -ErrorAction Stop
    } catch {
        throw 'The Windows Companion release-test inventory is not valid strict UTF-8 JSON.'
    }

    $topLevelProperties = @(
        'schemaVersion', 'projectPath', 'assemblyName', 'targetFramework',
        'adapterTypeName', 'expectedMethodCount', 'expectedCaseCount',
        'canonicalInventorySha256', 'tests'
    )
    $schemaVersion = [int]$document.schemaVersion
    if ($schemaVersion -eq 2) {
        $topLevelProperties += 'windowsTargetFramework'
    }
    Assert-JTSExactJsonProperties `
        -Value $document `
        -ExpectedNames $topLevelProperties `
        -Description 'Windows Companion release-test inventory'
    if ($schemaVersion -notin @(1, 2) -or
        [string]$document.projectPath -cne $ExpectedProjectPath -or
        [string]$document.assemblyName -notmatch '\A[A-Za-z0-9_.-]+\.dll\z' -or
        [string]$document.targetFramework -cnotmatch '\Anet[0-9]+(?:\.[0-9]+)+(?:-windows(?:[0-9]+(?:\.[0-9]+)+)?)?\z' -or
        [string]::IsNullOrWhiteSpace([string]$document.adapterTypeName) -or
        [int]$document.expectedMethodCount -le 0 -or
        [int]$document.expectedMethodCount -gt 100000 -or
        [int]$document.expectedCaseCount -le 0 -or
        [int]$document.expectedCaseCount -gt 1000000 -or
        [string]$document.canonicalInventorySha256 -notmatch '\A[0-9a-f]{64}\z') {
        throw 'The Windows Companion release-test inventory metadata is malformed or unexpected.'
    }
    $windowsTargetFramework = [string]$document.targetFramework
    if ($schemaVersion -eq 2) {
        $windowsTargetFramework = [string]$document.windowsTargetFramework
        if ($windowsTargetFramework -cnotmatch '\Anet[0-9]+(?:\.[0-9]+)+-windows(?:[0-9]+(?:\.[0-9]+)+)?\z' -or
            -not $windowsTargetFramework.StartsWith(
                ([string]$document.targetFramework + '-windows'), [StringComparison]::Ordinal)) {
            throw 'The Windows Companion inventory Windows target framework is malformed or inconsistent.'
        }
    }
    $targetFramework = [string]$document.targetFramework
    if ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows)) {
        $targetFramework = $windowsTargetFramework
    }

    $tests = @($document.tests)
    if ($tests.Count -ne [int]$document.expectedMethodCount) {
        throw 'The Windows Companion release-test inventory method count is internally inconsistent.'
    }
    $testsByKey = [Collections.Generic.Dictionary[string,object]]::new(
        [StringComparer]::Ordinal)
    $methodCaseCounts = [Collections.Generic.Dictionary[string,int]]::new(
        [StringComparer]::Ordinal)
    $caseCount = 0
    $interactiveUiAutomationTests = New-Object Collections.Generic.List[object]
    $interactiveConsentTests = New-Object Collections.Generic.List[object]
    $windowsIntegrationTests = New-Object Collections.Generic.List[object]
    foreach ($test in $tests) {
        Assert-JTSExactJsonProperties `
            -Value $test `
            -ExpectedNames @('key', 'caseCount', 'skipPolicy') `
            -Description 'Windows Companion release-test inventory entry'
        $key = [string]$test.key
        $testCaseCount = [int]$test.caseCount
        $skipPolicy = [string]$test.skipPolicy
        if ([string]::IsNullOrWhiteSpace($key) -or $key.Length -gt 512 -or
            $key -match '[\x00-\x1f\x7f]' -or
            $key -notmatch '\AJTS\.WindowsCompanion\.Tests\..+\..+\z' -or
            $testCaseCount -le 0 -or $testCaseCount -gt 10000 -or
            $skipPolicy -notin @(
                'never',
                'interactive-uia',
                'interactive-consent',
                'windows-integration'
            ) -or
            $testsByKey.ContainsKey($key)) {
            throw "The Windows Companion release-test inventory contains a malformed or duplicate entry: $key"
        }
        $normalized = [pscustomobject][ordered]@{
            key = $key
            caseCount = $testCaseCount
            skipPolicy = $skipPolicy
        }
        $testsByKey.Add($key, $normalized)
        $methodCaseCounts.Add($key, $testCaseCount)
        $caseCount += $testCaseCount
        if ($skipPolicy -eq 'interactive-uia') {
            $interactiveUiAutomationTests.Add($normalized)
        } elseif ($skipPolicy -eq 'interactive-consent') {
            $interactiveConsentTests.Add($normalized)
        } elseif ($skipPolicy -eq 'windows-integration') {
            $windowsIntegrationTests.Add($normalized)
        }
    }
    if ($caseCount -ne [int]$document.expectedCaseCount -or
        $interactiveUiAutomationTests.Count -ne 1 -or
        $interactiveConsentTests.Count -ne 2 -or
        $windowsIntegrationTests.Count -lt 1 -or
        [int]$interactiveUiAutomationTests[0].caseCount -ne 1 -or
        @($interactiveConsentTests | Where-Object {
            [int]$_.caseCount -ne 1
        }).Count -ne 0 -or
        @($windowsIntegrationTests | Where-Object {
            [int]$_.caseCount -ne 1
        }).Count -ne 0) {
        throw 'The Windows Companion release-test inventory case or skip-policy totals are inconsistent.'
    }
    $canonicalInventory = Get-JTSCanonicalMethodCaseInventory `
        -MethodCaseCounts $methodCaseCounts
    $canonicalInventorySha256 = Get-JTSSha256Hex `
        -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($canonicalInventory))
    if ($canonicalInventorySha256 -cne
        [string]$document.canonicalInventorySha256) {
        throw 'The Windows Companion release-test inventory canonical SHA-256 is internally inconsistent.'
    }

    return [pscustomobject][ordered]@{
        path = $input.path
        sha256 = $input.sha256
        projectPath = [string]$document.projectPath
        assemblyName = [string]$document.assemblyName
        targetFramework = $targetFramework
        baseTargetFramework = [string]$document.targetFramework
        windowsTargetFramework = $windowsTargetFramework
        adapterTypeName = [string]$document.adapterTypeName
        expectedMethodCount = [int]$document.expectedMethodCount
        expectedCaseCount = [int]$document.expectedCaseCount
        canonicalInventorySha256 = $canonicalInventorySha256
        testsByKey = $testsByKey
        interactiveUiAutomationTest = $interactiveUiAutomationTests[0]
        interactiveConsentTests = $interactiveConsentTests.ToArray()
        windowsIntegrationTests = $windowsIntegrationTests.ToArray()
    }
}

function Get-JTSTrxXmlDocument {
    param([Parameter(Mandatory)] [byte[]] $Bytes)

    try {
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $xmlText = $utf8.GetString($Bytes)
        if ($xmlText.Length -gt 0 -and [int]$xmlText[0] -eq 0xFEFF) {
            $xmlText = $xmlText.Substring(1)
        }
        $settings = [Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $stringReader = [IO.StringReader]::new($xmlText)
        $reader = [Xml.XmlReader]::Create($stringReader, $settings)
        try {
            $document = [Xml.XmlDocument]::new()
            $document.XmlResolver = $null
            $document.Load($reader)
        } finally {
            $reader.Dispose()
            $stringReader.Dispose()
        }
        return $document
    } catch {
        throw 'The Windows Companion TRX is not valid strict UTF-8 XML.'
    }
}

function Assert-JTSTestIdentityComponent {
    param(
        [Parameter(Mandatory)] [string] $Value,
        [Parameter(Mandatory)] [string] $Description
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt 512 -or
        $Value -match '[\x00-\x1f\x7f]') {
        throw "The Windows Companion TRX contains a malformed $Description."
    }
}

function Get-JTSTrxEvidence {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $InventoryPath,
        [Parameter(Mandatory)] [string] $ExpectedProjectPath,
        [switch] $RequireInteractiveUiAutomation,
        [switch] $RequireInteractiveConsent,
        [switch] $RequireWindowsIntegration
    )

    $inventory = Get-JTSReleaseTestInventory `
        -Path $InventoryPath `
        -ExpectedProjectPath $ExpectedProjectPath
    $input = Get-JTSSingleReadFileBytes `
        -Path $Path `
        -Description 'Windows Companion TRX result' `
        -MaximumLengthBytes 64MB
    $document = Get-JTSTrxXmlDocument -Bytes $input.bytes

    $summary = $document.SelectSingleNode("//*[local-name()='ResultSummary']")
    if ($null -eq $summary) {
        throw 'The Windows Companion TRX result has no result summary.'
    }
    $counters = $summary.SelectSingleNode("./*[local-name()='Counters']")
    if ($null -eq $counters -or [string]$summary.outcome -cne 'Completed') {
        throw 'The Windows Companion TRX result is missing a completed summary or counters.'
    }
    $requiredCounterNames = @(
        'total', 'executed', 'passed', 'failed', 'error', 'timeout', 'aborted',
        'inconclusive', 'passedButRunAborted', 'notRunnable', 'notExecuted',
        'disconnected', 'warning', 'completed', 'inProgress', 'pending'
    )
    $missingCounterNames = @($requiredCounterNames | Where-Object {
        -not $counters.HasAttribute($_)
    })
    if ($missingCounterNames.Count -ne 0) {
        throw "The Windows Companion TRX summary is missing counters: $($missingCounterNames -join ', ')"
    }

    $definitions = [Collections.Generic.Dictionary[string,object]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $unitTests = @($document.SelectNodes(
        "//*[local-name()='TestDefinitions']/*[local-name()='UnitTest']"))
    foreach ($unitTest in $unitTests) {
        $testId = [string]$unitTest.id
        $testName = [string]$unitTest.name
        $testMethod = $unitTest.SelectSingleNode("./*[local-name()='TestMethod']")
        if ($null -eq $testMethod) {
            throw 'The Windows Companion TRX contains a test definition without TestMethod metadata.'
        }
        $className = [string]$testMethod.className
        $methodName = [string]$testMethod.name
        $codeBase = [string]$testMethod.codeBase
        $adapterTypeName = [string]$testMethod.adapterTypeName
        Assert-JTSTestIdentityComponent -Value $testId -Description 'test definition ID'
        Assert-JTSTestIdentityComponent -Value $testName -Description 'test definition name'
        Assert-JTSTestIdentityComponent -Value $className -Description 'test class name'
        Assert-JTSTestIdentityComponent -Value $methodName -Description 'test method name'
        if ([IO.Path]::GetFileName($codeBase) -ine $inventory.assemblyName -or
            $adapterTypeName -cne $inventory.adapterTypeName -or
            $definitions.ContainsKey($testId)) {
            throw 'The Windows Companion TRX contains an unexpected adapter, assembly, or duplicate test definition.'
        }
        $definitions.Add($testId, [pscustomobject][ordered]@{
            testId = $testId
            testName = $testName
            key = ('{0}.{1}' -f $className, $methodName)
        })
    }

    $results = @($document.SelectNodes("//*[local-name()='UnitTestResult']"))
    $executionIds = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $resultTestIds = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $methodCaseCounts = [Collections.Generic.Dictionary[string,int]]::new(
        [StringComparer]::Ordinal)
    $normalizedResults = New-Object Collections.Generic.List[object]
    foreach ($result in $results) {
        $executionId = [string]$result.executionId
        $testId = [string]$result.testId
        Assert-JTSTestIdentityComponent -Value $executionId -Description 'execution ID'
        Assert-JTSTestIdentityComponent -Value $testId -Description 'result test ID'
        if (-not $executionIds.Add($executionId) -or
            -not $resultTestIds.Add($testId) -or
            -not $definitions.ContainsKey($testId)) {
            throw 'The Windows Companion TRX contains a duplicate or unbound test result.'
        }
        $definition = $definitions[$testId]
        if ([string]$result.testName -cne [string]$definition.testName) {
            throw 'The Windows Companion TRX result name is detached from its test definition.'
        }
        if ($methodCaseCounts.ContainsKey($definition.key)) {
            $methodCaseCounts[$definition.key] += 1
        } else {
            $methodCaseCounts.Add($definition.key, 1)
        }
        $normalizedResults.Add([pscustomobject][ordered]@{
            key = $definition.key
            outcome = [string]$result.outcome
        })
    }
    if ($results.Count -eq 0 -or $definitions.Count -ne $results.Count -or
        $resultTestIds.Count -ne $definitions.Count) {
        throw 'The Windows Companion TRX test definitions and results are incomplete or mismatched.'
    }

    $canonicalInventory = Get-JTSCanonicalMethodCaseInventory `
        -MethodCaseCounts $methodCaseCounts
    $actualInventorySha256 = Get-JTSSha256Hex `
        -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($canonicalInventory))
    $inventoryMismatch = $methodCaseCounts.Count -ne $inventory.expectedMethodCount -or
        $results.Count -ne $inventory.expectedCaseCount -or
        $actualInventorySha256 -cne $inventory.canonicalInventorySha256
    foreach ($expected in $inventory.testsByKey.Values) {
        if (-not $methodCaseCounts.ContainsKey($expected.key) -or
            $methodCaseCounts[$expected.key] -ne [int]$expected.caseCount) {
            $inventoryMismatch = $true
            break
        }
    }
    if ($inventoryMismatch) {
        throw ("The Windows Companion TRX does not match the complete release-test inventory " +
            "(actual methods={0}, cases={1}, SHA-256={2})." -f
            $methodCaseCounts.Count, $results.Count, $actualInventorySha256)
    }

    $notExecuted = @($normalizedResults | Where-Object { $_.outcome -eq 'NotExecuted' })
    $passed = @($normalizedResults | Where-Object { $_.outcome -eq 'Passed' })
    $failed = @($normalizedResults | Where-Object {
        $_.outcome -notin @('Passed', 'NotExecuted')
    })
    if ($failed.Count -ne 0 -or [int]$counters.failed -ne 0 -or
        [int]$counters.error -ne 0 -or [int]$counters.timeout -ne 0 -or
        [int]$counters.aborted -ne 0 -or [int]$counters.notRunnable -ne 0 -or
        [int]$counters.inconclusive -ne 0 -or
        [int]$counters.passedButRunAborted -ne 0 -or
        [int]$counters.disconnected -ne 0 -or [int]$counters.warning -ne 0 -or
        [int]$counters.completed -ne 0 -or [int]$counters.inProgress -ne 0 -or
        [int]$counters.pending -ne 0 -or
        [int]$counters.total -ne $results.Count -or
        [int]$counters.passed -ne $passed.Count -or
        [int]$counters.executed -ne $passed.Count -or
        ([int]$counters.total - [int]$counters.executed) -ne $notExecuted.Count) {
        throw 'The Windows Companion TRX contains failed, incomplete, or non-runnable tests.'
    }

    $interactiveUiAutomationKey = [string]$inventory.interactiveUiAutomationTest.key
    $interactiveUiAutomation = @($normalizedResults | Where-Object {
        $_.key -ceq $interactiveUiAutomationKey
    })
    if ($interactiveUiAutomation.Count -ne 1 -or
        $interactiveUiAutomation[0].outcome -notin @('Passed', 'NotExecuted')) {
        throw 'The exact independent-process UI Automation test is missing, duplicated, or has an invalid outcome.'
    }
    $interactiveConsentKeys = @($inventory.interactiveConsentTests | ForEach-Object {
        [string]$_.key
    })
    $interactiveConsent = @($normalizedResults | Where-Object {
        $_.key -cin $interactiveConsentKeys
    })
    if ($interactiveConsent.Count -ne $interactiveConsentKeys.Count -or
        @($interactiveConsent | Where-Object {
            $_.outcome -notin @('Passed', 'NotExecuted')
        }).Count -ne 0) {
        throw 'The exact interactive Companion consent tests are missing, duplicated, or have an invalid outcome.'
    }
    $windowsIntegrationKeys = @($inventory.windowsIntegrationTests | ForEach-Object {
        [string]$_.key
    })
    $windowsIntegration = @($normalizedResults | Where-Object {
        $_.key -cin $windowsIntegrationKeys
    })
    if ($windowsIntegration.Count -ne $windowsIntegrationKeys.Count -or
        @($windowsIntegration | Where-Object {
            $_.outcome -notin @('Passed', 'NotExecuted')
        }).Count -ne 0) {
        throw 'The exact Windows integration tests are missing, duplicated, or have an invalid outcome.'
    }
    if ($RequireInteractiveUiAutomation) {
        if ($interactiveUiAutomation[0].outcome -ne 'Passed') {
            throw 'Interactive UI Automation was required, but the exact independent-process test did not pass.'
        }
    }
    if ($RequireInteractiveConsent -and
        @($interactiveConsent | Where-Object {
            $_.outcome -ne 'Passed'
        }).Count -ne 0) {
        throw 'Interactive Companion consent was required, but both exact consent tests did not pass.'
    }
    if ($RequireWindowsIntegration -and
        @($windowsIntegration | Where-Object {
            $_.outcome -ne 'Passed'
        }).Count -ne 0) {
        throw 'Windows integration was required, but one or more exact native tests did not pass.'
    }
    $unexpectedSkipped = @($notExecuted | Where-Object {
        $entry = $inventory.testsByKey[[string]$_.key]
        $null -eq $entry -or
        [string]$entry.skipPolicy -eq 'never' -or
        ([string]$entry.skipPolicy -eq 'interactive-uia' -and
            $RequireInteractiveUiAutomation) -or
        ([string]$entry.skipPolicy -eq 'interactive-consent' -and
            $RequireInteractiveConsent) -or
        ([string]$entry.skipPolicy -eq 'windows-integration' -and
            $RequireWindowsIntegration)
    })
    if ($unexpectedSkipped.Count -ne 0) {
        throw 'The Windows Companion TRX contains an unexpected or required interactive skipped test.'
    }

    $interactiveConsentOutcomes = [ordered]@{}
    foreach ($result in $interactiveConsent) {
        $interactiveConsentOutcomes[[string]$result.key] = [string]$result.outcome
    }
    $windowsIntegrationOutcomes = [ordered]@{}
    foreach ($result in $windowsIntegration) {
        $windowsIntegrationOutcomes[[string]$result.key] = [string]$result.outcome
    }

    return [pscustomobject][ordered]@{
        path = $input.path
        sha256 = $input.sha256
        inventoryPath = $inventory.path
        inventorySha256 = $inventory.sha256
        expectedMethodCount = $inventory.expectedMethodCount
        actualMethodCount = $methodCaseCounts.Count
        expectedCaseCount = $inventory.expectedCaseCount
        actualCaseCount = $results.Count
        canonicalInventorySha256 = $actualInventorySha256
        inventoryMatched = $true
        total = [int]$counters.total
        passed = [int]$counters.passed
        failed = [int]$counters.failed
        skipped = $notExecuted.Count
        interactiveUiAutomationRequired = $RequireInteractiveUiAutomation.IsPresent
        interactiveUiAutomationOutcome = $interactiveUiAutomation[0].outcome
        interactiveConsentRequired = $RequireInteractiveConsent.IsPresent
        interactiveConsentOutcomes = $interactiveConsentOutcomes
        windowsIntegrationRequired = $RequireWindowsIntegration.IsPresent
        windowsIntegrationOutcomes = $windowsIntegrationOutcomes
    }
}
