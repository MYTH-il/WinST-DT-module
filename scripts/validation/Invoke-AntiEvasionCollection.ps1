param(
    [string]$AlKhaserPath,

    [string]$PafishPath,

    [string[]]$AlKhaserArguments = @("--check", "GEN_SANDBOX", "--check", "QEMU", "--check", "KVM", "--check", "HYPERV", "--check", "VBOX", "--check", "VMWARE", "--sleep", "5"),

    [string[]]$PafishArguments = @(),

    [string]$OutputRoot = "C:\ProgramData\WinSTDT\validation\anti-evasion",

    [int]$TimeoutSeconds = 300
)

$ErrorActionPreference = "Stop"

function New-Directory {
    param([string]$Path)
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
}

function Write-JsonFile {
    param(
        [string]$Path,
        [object]$Value
    )
    $Value | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Assert-Tool {
    param(
        [string]$Path,
        [string]$Name
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Name path not found: $Path"
    }
    $item = Get-Item -LiteralPath $Path
    if (-not $item.PSIsContainer -and $item.Length -le 0) {
        throw "$Name file is empty: $Path"
    }
}

function Invoke-ValidationTool {
    param(
        [string]$Name,
        [string]$Path,
        [string[]]$Arguments,
        [string]$RunRoot,
        [int]$Timeout
    )

    $stdoutPath = Join-Path $RunRoot "$Name.stdout.txt"
    $stderrPath = Join-Path $RunRoot "$Name.stderr.txt"
    $resultPath = Join-Path $RunRoot "$Name.result.json"
    $toolRunRoot = Join-Path $RunRoot $Name
    New-Directory -Path $toolRunRoot
    $toolCopyPath = Join-Path $toolRunRoot (Split-Path -Leaf $Path)
    Copy-Item -LiteralPath $Path -Destination $toolCopyPath -Force

    $startInfo = @{
        FilePath = $toolCopyPath
        WorkingDirectory = $toolRunRoot
        PassThru = $true
        WindowStyle = "Hidden"
        RedirectStandardOutput = $stdoutPath
        RedirectStandardError = $stderrPath
    }
    if ($Arguments.Count -gt 0) {
        $startInfo.ArgumentList = $Arguments
    }
    $process = Start-Process @startInfo
    $deadline = (Get-Date).AddSeconds($Timeout)
    while ((Get-Date) -lt $deadline) {
        $process.Refresh()
        if ($process.HasExited) {
            break
        }
        Start-Sleep -Milliseconds 500
    }
    $process.Refresh()
    $completed = $process.HasExited
    if (-not $completed) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        $process.WaitForExit(5000) | Out-Null
    } else {
        $process.WaitForExit() | Out-Null
    }

    $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $Path
    $result = [ordered]@{
        name = $Name
        path = $Path
        staged_path = $toolCopyPath
        working_directory = $toolRunRoot
        arguments = $Arguments
        sha256 = $hash.Hash.ToLowerInvariant()
        started_utc = $script:StartedUtc
        completed = $completed
        exit_code = if ($completed) { $process.ExitCode } else { $null }
        timed_out = -not $completed
        stdout = $stdoutPath
        stderr = $stderrPath
        note = "Map this raw output manually into docs/validation/golden_image_report_current.md strict-subset categories."
    }
    Write-JsonFile -Path $resultPath -Value $result
    return $result
}

if ([string]::IsNullOrWhiteSpace($AlKhaserPath) -and [string]::IsNullOrWhiteSpace($PafishPath)) {
    throw "At least one validation tool path must be provided."
}
if (-not [string]::IsNullOrWhiteSpace($AlKhaserPath)) {
    Assert-Tool -Path $AlKhaserPath -Name "al-khaser"
}
if (-not [string]::IsNullOrWhiteSpace($PafishPath)) {
    Assert-Tool -Path $PafishPath -Name "Pafish"
}

$script:StartedUtc = (Get-Date).ToUniversalTime().ToString("o")
$runId = "anti-evasion-{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss")
$runRoot = Join-Path $OutputRoot $runId
New-Directory -Path $runRoot

$system = [ordered]@{
    collected_utc = $script:StartedUtc
    computer_name = $env:COMPUTERNAME
    user_name = $env:USERNAME
    windows_version = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture)
    computer_system = (Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, TotalPhysicalMemory, NumberOfLogicalProcessors, Workgroup)
    bios = (Get-CimInstance Win32_BIOS | Select-Object Manufacturer, SMBIOSBIOSVersion, SerialNumber, Version)
    processors = (Get-CimInstance Win32_Processor | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors)
    disks = (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID, Size, FreeSpace)
}
Write-JsonFile -Path (Join-Path $runRoot "system-context.json") -Value $system

$tools = @()
if (-not [string]::IsNullOrWhiteSpace($AlKhaserPath)) {
    $tools += Invoke-ValidationTool -Name "al-khaser" -Path $AlKhaserPath -Arguments $AlKhaserArguments -RunRoot $runRoot -Timeout $TimeoutSeconds
}
if (-not [string]::IsNullOrWhiteSpace($PafishPath)) {
    $tools += Invoke-ValidationTool -Name "pafish" -Path $PafishPath -Arguments $PafishArguments -RunRoot $runRoot -Timeout $TimeoutSeconds
}

$summary = [ordered]@{
    schema_version = "1.0"
    run_id = $runId
    output_root = $runRoot
    tools = $tools
    required_report = "docs/validation/golden_image_report_current.md"
    decision_rule = "Manual strict-subset mapping required; any required category failure rejects MVP image."
}
Write-JsonFile -Path (Join-Path $runRoot "summary.json") -Value $summary

Write-Host "Anti-evasion collection complete: $runRoot"
Write-Host "Attach summary.json, system-context.json, stdout, stderr, and tool hashes to the golden image report."
