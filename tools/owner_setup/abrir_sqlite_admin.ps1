param([switch]$Check, [switch]$Console)
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot 'sqlite_admin_setup.py'
$pythonPath = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$scriptArgs = @($scriptPath)
if ($Check) { $scriptArgs += '--check' }
if ($Console) { $scriptArgs += '--console' }
if (Test-Path -LiteralPath $pythonPath) {
    & $pythonPath @scriptArgs
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 @scriptArgs
} else {
    & python @scriptArgs
}
exit $LASTEXITCODE
