param([switch]$Console, [switch]$Owner, [switch]$Staging)
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot 'ratchet_owner_setup.py'
$scriptArgs = @($scriptPath)
if ($Console) { $scriptArgs += '--console' }
elseif ($Owner) { $scriptArgs += '--owner' }
else { $scriptArgs += '--admin' }
$previousOrigin = $env:RATCHET_RUST_ORIGIN
$previousToken = $env:RATCHET_RUST_BOOTSTRAP_TOKEN
try {
    if ($Staging) {
        $repository = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        $configuration = Get-Content -LiteralPath (Join-Path $repository 'wrangler.staging.jsonc') -Raw | ConvertFrom-Json
        $env:RATCHET_RUST_ORIGIN = $configuration.vars.RP_ORIGIN
        $secretsPath = Join-Path $repository '.dev.vars.staging.json'
        if (-not $Console -and (Test-Path -LiteralPath $secretsPath)) {
            $secrets = Get-Content -LiteralPath $secretsPath -Raw | ConvertFrom-Json
            $env:RATCHET_RUST_BOOTSTRAP_TOKEN = $secrets.BOOTSTRAP_TOKEN
        }
    }
    if (Get-Command py -ErrorAction SilentlyContinue) { & py -3 @scriptArgs }
    elseif (Get-Command python -ErrorAction SilentlyContinue) { & python @scriptArgs }
    else { throw 'Python no está disponible. Prepará Python con Tk y cryptography para abrir la consola.' }
    $result = $LASTEXITCODE
} finally {
    $env:RATCHET_RUST_ORIGIN = $previousOrigin
    $env:RATCHET_RUST_BOOTSTRAP_TOKEN = $previousToken
}
exit $result
