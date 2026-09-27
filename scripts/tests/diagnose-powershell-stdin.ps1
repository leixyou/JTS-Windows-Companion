# Read-only synthetic child-process diagnostic for an isolated Windows CI runner.
# Run with pwsh; never reads user scripts, credentials, files or configuration.
$ErrorActionPreference = 'Stop'
$sample = '$名字 = ''中文é🚀''; [Console]::Out.Write($名字); [Console]::Error.Write($名字); exit 7'
$prefix = @'
[Console]::Error.WriteLine('JTS:entry')
$utf8 = New-Object System.Text.UTF8Encoding($false)
[Console]::InputEncoding = $utf8
[Console]::Error.WriteLine('JTS:input-set')
[Console]::OutputEncoding = $utf8
$OutputEncoding = $utf8
[Console]::Error.WriteLine('JTS:output-set')
'@
$readConsole = '$code = [Console]::In.ReadToEnd()'
$readRaw = '$reader = New-Object System.IO.StreamReader([Console]::OpenStandardInput(), $utf8, $false); $code = $reader.ReadToEnd()'
$variants = @(
    @{Name='encoded-no-read'; Encoded=$true; Body=$prefix + "`n[Console]::Error.WriteLine('JTS:no-read'); exit 7"},
    @{Name='encoded-console'; Encoded=$true; Body=$prefix + "`n[Console]::Error.WriteLine('JTS:read-start')`n" + $readConsole},
    @{Name='encoded-raw-stream'; Encoded=$true; Body=$prefix + "`n[Console]::Error.WriteLine('JTS:read-start')`n" + $readRaw},
    @{Name='command-console'; Encoded=$false; Body=$prefix + "`n[Console]::Error.WriteLine('JTS:read-start')`n" + $readConsole},
    @{Name='command-raw-stream'; Encoded=$false; Body=$prefix + "`n[Console]::Error.WriteLine('JTS:read-start')`n" + $readRaw}
)
foreach ($variant in $variants) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $start.UseShellExecute = $false; $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true; $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
    $start.StandardInputEncoding = [Text.UTF8Encoding]::new($false)
    $start.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
    $start.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
    foreach ($argument in @('-NoLogo','-NoProfile','-NonInteractive','-OutputFormat','Text')) { $start.ArgumentList.Add($argument) }
    $body = $variant.Body + "`n[Console]::Error.WriteLine('JTS:read-done'); & ([ScriptBlock]::Create(`$code)); [Console]::Error.WriteLine('JTS:eval-done')"
    if ($variant.Encoded) {
        $start.ArgumentList.Add('-EncodedCommand')
        $start.ArgumentList.Add([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body)))
    } else { $start.ArgumentList.Add('-Command'); $start.ArgumentList.Add($body) }
    $process = [Diagnostics.Process]::new(); $process.StartInfo = $start
    $watch = [Diagnostics.Stopwatch]::StartNew(); [void]$process.Start()
    $stdout = $process.StandardOutput.ReadToEndAsync(); $stderr = $process.StandardError.ReadToEndAsync()
    $inputError = $null
    try { $process.StandardInput.Write($sample); $process.StandardInput.Close() }
    catch { $inputError = $_.Exception.GetType().Name }
    $done = $process.WaitForExit(8000)
    if (-not $done) { $process.Kill($true); [void]$process.WaitForExit(5000) }
    [void][Threading.Tasks.Task]::WaitAll(@($stdout,$stderr),5000)
    $result = @{name=$variant.Name; completed=$done; elapsedMilliseconds=$watch.ElapsedMilliseconds; exitCode=$process.ExitCode; inputError=$inputError;
        stdout= $(if ($stdout.IsCompletedSuccessfully) { $stdout.Result } else { 'DIAGNOSTIC_READ_NOT_COMPLETED' });
        stderr= $(if ($stderr.IsCompletedSuccessfully) { $stderr.Result } else { 'DIAGNOSTIC_READ_NOT_COMPLETED' })}
    $result | ConvertTo-Json -Compress
    $process.Dispose()
}
