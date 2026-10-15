param([switch]$Console, [switch]$Owner)
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot 'ratchet_owner_setup.py'
$scriptArgs = @($scriptPath)
if ($Console) { $scriptArgs += '--console' }
elseif ($Owner) { $scriptArgs += '--owner' }
else { $scriptArgs += '--admin' }
if (Get-Command py -ErrorAction SilentlyContinue) { & py -3 @scriptArgs }
elseif (Get-Command python -ErrorAction SilentlyContinue) { & python @scriptArgs }
else { throw 'Python no está disponible. Prepará Python con Tk y cryptography para abrir la consola.' }
exit $LASTEXITCODE
