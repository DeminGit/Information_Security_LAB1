$ErrorActionPreference = 'Stop'
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $env:TEST_DB_PASSWORD = [Convert]::ToBase64String($bytes)
    $env:TEST_DB_URL = 'jdbc:postgresql://localhost:55432/secure_notes_test'
    $env:TEST_DB_USER = 'test_user'
    docker compose -f compose.test.yml up -d --wait
    if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL failed to start' }
    mvn -B -ntp '-Ddebug=false' verify
    if ($LASTEXITCODE -ne 0) { throw 'Tests or SAST failed' }
} finally {
    docker compose -f compose.test.yml down
    Pop-Location
}
