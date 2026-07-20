param(
    [string]$SourceBinary = ".\winstdt.exe",
    [string]$SourceConfig = ".\etw-agent.config.json",
    [string]$InstallRoot = "C:\ProgramData\WinSTDT",
    [string]$TestUrl = "http://example.com",
    [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an elevated PowerShell session."
    }
}

function Read-AgentConfig {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Config not found: $Path"
    }
    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Stop-ExistingSession {
    param([string]$SessionName)
    & logman stop $SessionName -ets | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "No existing ETW session named $SessionName, continuing."
    }
}

function Install-Agent {
    param(
        [string]$Binary,
        [string]$Config,
        [string]$Root
    )

    $binDir = Join-Path $Root "bin"
    $behaviorDir = Join-Path $Root "behavior"
    New-Item -ItemType Directory -Force -Path $binDir | Out-Null
    New-Item -ItemType Directory -Force -Path $behaviorDir | Out-Null

    if (-not (Test-Path -LiteralPath $Binary)) {
        throw "Source binary not found: $Binary"
    }
    if (-not (Test-Path -LiteralPath $Config)) {
        throw "Source config not found: $Config"
    }

    Copy-Item -LiteralPath $Binary -Destination (Join-Path $binDir "winstdt.exe") -Force
    Copy-Item -LiteralPath $Config -Destination (Join-Path $Root "etw-agent.config.json") -Force
}

function Invoke-BenignActivity {
    param([string]$Url)

    $testFile = "C:\Users\Public\winstdt-etw-validation.txt"
    $registryPath = "HKCU:\Software\WinSTDTValidation"

    Start-Process notepad.exe
    Start-Sleep -Milliseconds 750
    Get-Process notepad -ErrorAction SilentlyContinue | Stop-Process -Force

    New-Item -ItemType File -Force -Path $testFile | Out-Null
    Set-Content -LiteralPath $testFile -Value "WinSTDT ETW validation"
    Remove-Item -LiteralPath $testFile -Force

    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name TestValue -Value "ok" -Force | Out-Null
    Remove-ItemProperty -Path $registryPath -Name TestValue -ErrorAction SilentlyContinue
    Remove-Item -Path $registryPath -Force -ErrorAction SilentlyContinue

    Resolve-DnsName example.com -ErrorAction SilentlyContinue | Out-Null
    try {
        Invoke-WebRequest $Url -UseBasicParsing -TimeoutSec 5 | Out-Null
    } catch {
        Write-Host "Network request did not complete, continuing: $($_.Exception.Message)"
    }
}

function Assert-Output {
    param(
        [string]$TracePath,
        [string]$TelemetryPath
    )

    if (-not (Test-Path -LiteralPath $TracePath)) {
        throw "ETL trace missing: $TracePath"
    }
    $trace = Get-Item -LiteralPath $TracePath
    if ($trace.Length -le 0) {
        throw "ETL trace is empty: $TracePath"
    }

    if (-not (Test-Path -LiteralPath $TelemetryPath)) {
        throw "Telemetry metadata missing: $TelemetryPath"
    }
    $telemetry = Get-Content -LiteralPath $TelemetryPath -Raw | ConvertFrom-Json
    if ($telemetry.capture_started -ne $true) {
        throw "telemetry.capture_started was not true"
    }
    if ($telemetry.capture_completed -ne $true) {
        throw "telemetry.capture_completed was not true"
    }
    if (-not $telemetry.providers_targeted -or $telemetry.providers_targeted.Count -eq 0) {
        throw "telemetry.providers_targeted is empty"
    }

    Write-Host "ETW validation passed."
    Write-Host "Trace: $TracePath ($($trace.Length) bytes)"
    Write-Host "Telemetry degraded: $($telemetry.telemetry_degraded)"
    Write-Host "Providers enabled: $($telemetry.providers_enabled -join ', ')"
    if ($telemetry.providers_unavailable) {
        Write-Host "Providers unavailable:"
        $telemetry.providers_unavailable | Format-Table provider, reason, message -AutoSize
    }
}

Assert-Administrator

if (-not $SkipInstall) {
    Install-Agent -Binary $SourceBinary -Config $SourceConfig -Root $InstallRoot
}

$agent = Join-Path $InstallRoot "bin\winstdt.exe"
$configPath = Join-Path $InstallRoot "etw-agent.config.json"
$config = Read-AgentConfig -Path $configPath

Stop-ExistingSession -SessionName $config.session_name

Remove-Item -LiteralPath $config.trace_path -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $config.telemetry_path -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $config.state_path -Force -ErrorAction SilentlyContinue

& $agent etw-agent --config $configPath start
if ($LASTEXITCODE -ne 0) {
    throw "ETW agent start failed with exit code $LASTEXITCODE"
}

try {
    Invoke-BenignActivity -Url $TestUrl
} finally {
    & $agent etw-agent --config $configPath stop
    if ($LASTEXITCODE -ne 0) {
        throw "ETW agent stop failed with exit code $LASTEXITCODE"
    }
}

Assert-Output -TracePath $config.trace_path -TelemetryPath $config.telemetry_path
