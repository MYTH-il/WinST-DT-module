param(
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

    [switch]$Apply
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Config file not found: $ConfigPath"
}

$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$mode = if ($Apply) { "APPLY" } else { "DRY-RUN" }

Write-Host "Guest hardening mode: $mode"
Write-Host "Build ID: $($config.build_id)"

function Write-Step {
    param(
        [string]$Name,
        [string]$Detail
    )

    Write-Host "[$Name] $Detail"
}

function Assert-MinimumResourceBaseline {
    param($ResourceConfig)

    $computer = Get-CimInstance Win32_ComputerSystem
    $processors = Get-CimInstance Win32_Processor
    $drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"

    $cpuCount = ($processors | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
    $ramGb = [math]::Round($computer.TotalPhysicalMemory / 1GB, 2)
    $diskGb = [math]::Round(($drives | Measure-Object -Property Size -Sum).Sum / 1GB, 2)
    $freeGb = [math]::Round(($drives | Measure-Object -Property FreeSpace -Sum).Sum / 1GB, 2)

    Write-Step "resources" "CPU=$cpuCount RAM_GB=$ramGb DISK_GB=$diskGb FREE_GB=$freeGb"

    if ($cpuCount -lt $ResourceConfig.minimum_cpu_count) {
        throw "CPU count is below baseline: $cpuCount"
    }
    if ($ramGb -lt $ResourceConfig.minimum_ram_gb) {
        throw "RAM is below baseline: $ramGb GB"
    }
    if ($diskGb -lt $ResourceConfig.minimum_disk_gb) {
        throw "Disk size is below baseline: $diskGb GB"
    }
    if ($freeGb -lt $ResourceConfig.minimum_free_disk_gb) {
        throw "Free disk is below baseline: $freeGb GB"
    }
}

function Test-BlockedName {
    param(
        [string]$Value,
        [string[]]$BlockedTerms,
        [string]$FieldName
    )

    foreach ($term in $BlockedTerms) {
        if ($Value -match [regex]::Escape($term)) {
            throw "$FieldName contains blocked term '$term': $Value"
        }
    }
}

function Assert-IdentityBaseline {
    param($IdentityConfig)

    $computerName = $env:COMPUTERNAME
    $userName = $env:USERNAME
    $workgroup = (Get-CimInstance Win32_ComputerSystem).Workgroup

    Write-Step "identity" "computer=$computerName user=$userName workgroup=$workgroup"

    Test-BlockedName -Value $computerName -BlockedTerms $IdentityConfig.blocked_terms -FieldName "Computer name"
    Test-BlockedName -Value $userName -BlockedTerms $IdentityConfig.blocked_terms -FieldName "User name"
    if ($workgroup) {
        Test-BlockedName -Value $workgroup -BlockedTerms $IdentityConfig.blocked_terms -FieldName "Workgroup"
    }
}

function Ensure-DirectorySeed {
    param(
        [string]$Path,
        [int]$MinimumFiles
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        if ($Apply) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }
        Write-Step "filesystem" "would create directory $Path"
        return
    }

    $count = (Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Step "filesystem" "$Path contains $count entries"

    if ($count -lt $MinimumFiles) {
        if ($Apply) {
            $missing = $MinimumFiles - $count
            for ($i = 1; $i -le $missing; $i++) {
                $seedPath = Join-Path $Path ("seed-{0}.txt" -f ([guid]::NewGuid().ToString("N").Substring(0, 8)))
                "validation seed" | Set-Content -LiteralPath $seedPath -Encoding ASCII
            }
        } else {
            Write-Step "filesystem" "would seed $Path to minimum $MinimumFiles entries"
        }
    }
}

function Invoke-ProfileSeeding {
    param($ProfileConfig)

    foreach ($directory in $ProfileConfig.directories) {
        $expandedPath = [Environment]::ExpandEnvironmentVariables($directory.path)
        Ensure-DirectorySeed -Path $expandedPath -MinimumFiles $directory.minimum_files
    }
}

Assert-MinimumResourceBaseline -ResourceConfig $config.resources
Assert-IdentityBaseline -IdentityConfig $config.identity
Invoke-ProfileSeeding -ProfileConfig $config.profile

Write-Host "Guest hardening checks completed."
if (-not $Apply) {
    Write-Host "Dry-run only. Re-run with -Apply to make filesystem seeding changes."
}
