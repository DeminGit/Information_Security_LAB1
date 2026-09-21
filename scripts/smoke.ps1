param([string]$BaseUrl = 'http://localhost:8080')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$local = Join-Path $root '.local'
New-Item -ItemType Directory -Force $local | Out-Null
$values = @{}
foreach ($line in Get-Content (Join-Path $root '.env')) {
    if ($line -match '^([A-Z_]+)=(.*)$') { $values[$Matches[1]] = $Matches[2] }
}
$utf8 = New-Object Text.UTF8Encoding $false
$loginFile = Join-Path $local 'login.json'
$tokenConfig = Join-Path $local 'curl-auth.conf'
$bodyFile = Join-Path $local 'response.json'
$noteFile = Join-Path $local 'note.json'
function Invoke-CurlCheck([string]$Method, [string]$Path, [int]$Expected, [string]$InputFile, [bool]$Authenticated) {
    $curlArgs = @('--silent', '--show-error', '--max-time', '15', '--output', $bodyFile, '--write-out', '%{http_code}', '-X', $Method)
    if ($Authenticated) { $curlArgs += @('--config', $tokenConfig) }
    if ($InputFile) { $curlArgs += @('-H', 'Content-Type: application/json', '--data-binary', ('@' + $InputFile)) }
    $status = & curl.exe @curlArgs ($BaseUrl + $Path)
    if ($LASTEXITCODE -ne 0 -or [int]$status -ne $Expected) { throw "$Method $Path : expected $Expected, got $status" }
    Write-Output "PASS $Method $Path -> $status"
}
try {
    [IO.File]::WriteAllText($loginFile, (@{username=$values.BOOTSTRAP_USERNAME; password=$values.BOOTSTRAP_PASSWORD} | ConvertTo-Json -Compress), $utf8)
    Invoke-CurlCheck 'GET' '/api/data' 401 '' $false
    Invoke-CurlCheck 'POST' '/auth/login' 200 $loginFile $false
    $token = (Get-Content $bodyFile -Raw | ConvertFrom-Json).accessToken
    [IO.File]::WriteAllText($tokenConfig, ('header = "Authorization: Bearer ' + $token + '"'), $utf8)
    [IO.File]::WriteAllText($noteFile, (@{title='<script>alert(1)</script>'; content="'); DROP TABLE notes; --"} | ConvertTo-Json -Compress), $utf8)
    Invoke-CurlCheck 'POST' '/api/data' 201 $noteFile $true
    $note = Get-Content $bodyFile -Raw | ConvertFrom-Json
    if ($note.title -ne '&lt;script&gt;alert(1)&lt;/script&gt;') { throw 'XSS escaping failed' }
    Write-Output 'PASS XSS escaped; SQL payload stored as data'
    Invoke-CurlCheck 'GET' '/api/data?limit=5' 200 '' $true
    [IO.File]::WriteAllText($loginFile, (@{username="' OR '1'='1' --"; password='wrong-password'} | ConvertTo-Json -Compress), $utf8)
    Invoke-CurlCheck 'POST' '/auth/login' 401 $loginFile $false
} finally {
    # Only the four explicitly created files inside this project's .local directory.
    foreach ($file in @($loginFile, $tokenConfig, $bodyFile, $noteFile)) {
        if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file }
    }
}
