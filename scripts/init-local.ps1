$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$path = Join-Path $root '.env'
if (Test-Path -LiteralPath $path) { throw '.env already exists; it was not overwritten.' }
function New-Secret {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    [Convert]::ToBase64String($bytes)
}
$lines = @('POSTGRES_DB=secure_notes', 'POSTGRES_USER=secure_notes',
    ('POSTGRES_PASSWORD=' + (New-Secret)), ('JWT_SECRET=' + (New-Secret)),
    'BOOTSTRAP_USERNAME=student', ('BOOTSTRAP_PASSWORD=' + (New-Secret)))
[IO.File]::WriteAllLines($path, $lines, (New-Object Text.UTF8Encoding $false))
Write-Output 'Created .env with random secrets. The file is ignored by Git. Use it locally; do not publish it.'
