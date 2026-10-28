# cfgtool end-to-end CLI benchmark (Windows PowerShell 5.1 / PowerShell 7).
# Measures complete process startup, JSON RPC, serialization, password KDF, crypto, and file I/O.
# Uses synthetic data in a disposable temporary directory. It never reads user configuration files.

param(
    [string]$Binary = (Join-Path $PSScriptRoot 'target\release\cfgtool.exe'),
    [ValidateRange(1, 100)]
    [int]$Runs = 3,
    [switch]$AllCombinations
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    throw "Release executable not found: $Binary. Run 'cargo build --release' first."
}
$Binary = (Resolve-Path -LiteralPath $Binary).Path

function Invoke-CfgtoolRpc {
    param([hashtable]$Request)

    $requestJson = ConvertTo-Json -InputObject $Request -Compress -Depth 12
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $Binary
    $startInfo.Arguments = 'rpc'
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $process = [System.Diagnostics.Process]::Start($startInfo)
    try {
        $process.StandardInput.Write($requestJson)
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        $watch.Stop()
        if ($process.ExitCode -ne 0) {
            throw "cfgtool exited with code $($process.ExitCode). $stderr $stdout"
        }
        $response = ConvertFrom-Json -InputObject $stdout
        if ($response.ok -ne $true) {
            throw "cfgtool returned an error: $stdout"
        }
        return [pscustomobject]@{
            Ms = $watch.Elapsed.TotalMilliseconds
            Response = $response
        }
    }
    finally {
        if (-not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
        $process.Dispose()
    }
}

function Get-Percentile {
    param([double[]]$Numbers, [double]$Percentile)
    $ordered = @($Numbers | Sort-Object)
    $index = [int][Math]::Ceiling(($Percentile / 100.0) * $ordered.Count) - 1
    $index = [Math]::Max(0, [Math]::Min($index, $ordered.Count - 1))
    return [double]$ordered[$index]
}

$temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) ('cfgtool-bench-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temporaryDirectory) | Out-Null

$cases = @(
    @{ Name = 'Plain JSON'; Format = 'json'; Cipher = $null; Kdf = $null },
    @{ Name = 'Plain XML'; Format = 'xml'; Cipher = $null; Kdf = $null },
    @{ Name = 'Plain .env'; Format = 'env'; Cipher = $null; Kdf = $null }
)

$ciphers = @('aes-256-gcm', 'aes-256-cbc+hmac-sha256', 'xchacha20-poly1305')
$kdfs = @('argon2id', 'pbkdf2-sha256', 'scrypt')
if ($AllCombinations) {
    foreach ($cipher in $ciphers) {
        foreach ($kdf in $kdfs) {
            $cases += @{ Name = "$cipher / $kdf"; Format = 'json'; Cipher = $cipher; Kdf = $kdf }
        }
    }
}
else {
    $cases += @(
        @{ Name = 'AES-GCM / Argon2id (default)'; Format = 'json'; Cipher = 'aes-256-gcm'; Kdf = 'argon2id' },
        @{ Name = 'AES-GCM / PBKDF2'; Format = 'json'; Cipher = 'aes-256-gcm'; Kdf = 'pbkdf2-sha256' },
        @{ Name = 'AES-GCM / scrypt'; Format = 'json'; Cipher = 'aes-256-gcm'; Kdf = 'scrypt' },
        @{ Name = 'CBC-HMAC / Argon2id'; Format = 'json'; Cipher = 'aes-256-cbc+hmac-sha256'; Kdf = 'argon2id' },
        @{ Name = 'XChaCha20 / Argon2id'; Format = 'json'; Cipher = 'xchacha20-poly1305'; Kdf = 'argon2id' }
    )
}

$sample = @{
    name = 'benchmark'
    enabled = $true
    database = @{ host = 'localhost'; port = 27017; pool = 12 }
    flags = @('alpha', 'beta', 'gamma')
    payload = ('x' * 4096)
}
$envSample = @{
    NAME = 'benchmark'
    HOST = 'localhost'
    MODE = 'test'
    PAYLOAD = ('x' * 4096)
}

Write-Host "cfgtool release benchmark: $Binary"
Write-Host "Runs per case: $Runs (one write and one read each run)"
Write-Host "Measurements include process startup, JSON RPC, KDF, crypto and file I/O."
Write-Host 'All data is synthetic; a temporary directory is removed afterward.'
Write-Host ''

$results = @()
try {
    $caseNumber = 0
    foreach ($case in $cases) {
        $caseNumber++
        $filePath = Join-Path $temporaryDirectory ("case-$caseNumber.cfg")
        $data = if ($case.Format -eq 'env') { $envSample } else { $sample }
        $writeTimings = @()
        $readTimings = @()
        for ($i = 0; $i -lt $Runs; $i++) {
            $writeRequest = @{
                op = 'write'; file = $filePath; format = $case.Format
                data = $data; overwrite = $true
            }
            $readRequest = @{ op = 'read'; file = $filePath }
            if ($null -ne $case.Cipher) {
                $writeRequest.encrypted = $true
                $writeRequest.cipher = $case.Cipher
                $writeRequest.kdf = $case.Kdf
                $writeRequest.password = 'synthetic-benchmark-password'
                $readRequest.password = 'synthetic-benchmark-password'
            }

            $writeResult = Invoke-CfgtoolRpc -Request $writeRequest
            $readResult = Invoke-CfgtoolRpc -Request $readRequest
            if ($readResult.Response.data.name -ne 'benchmark' -and $readResult.Response.data.NAME -ne 'benchmark') {
                throw "Read-back validation failed for $($case.Name)"
            }
            $writeTimings += [double]$writeResult.Ms
            $readTimings += [double]$readResult.Ms
        }
        $results += [pscustomobject]@{
            Case = $case.Name
            WriteMedianMs = [Math]::Round((Get-Percentile -Numbers $writeTimings -Percentile 50), 1)
            ReadMedianMs = [Math]::Round((Get-Percentile -Numbers $readTimings -Percentile 50), 1)
            ReadP95Ms = [Math]::Round((Get-Percentile -Numbers $readTimings -Percentile 95), 1)
        }
        Write-Host "Completed $caseNumber/$($cases.Count): $($case.Name)"
    }
}
finally {
    if (Test-Path -LiteralPath $temporaryDirectory) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}

Write-Host ''
$results | Format-Table -AutoSize
Write-Host 'P95 from very few samples is indicative only. Use -Runs 20 for more stable figures.'
