$ErrorActionPreference = 'Stop'
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    if (Test-Path .env) {
        foreach ($line in Get-Content .env) {
            if ($line -match '^NVD_API_KEY=(.+)$') { $env:NVD_API_KEY = $Matches[1].Trim() }
        }
    }
    mvn -B -ntp -Psca -DskipTests dependency-check:check
    if ($LASTEXITCODE -ne 0) { throw 'SCA did not pass. Inspect the Maven output and target/dependency-check-report.html.' }
} finally { Pop-Location }
