param(
    [string]$WorkRoot = "$env:ProgramData\WinSTDT\benign-detonation",
    [string]$EgressUrl = "http://10.66.0.1:8080/winstdt/benign-validation",
    [string]$DnsName = "benign-validation.winstdt.test"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $WorkRoot | Out-Null

$child = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList "/c exit 0" -PassThru -WindowStyle Hidden
$child.WaitForExit()

$filePath = Join-Path $WorkRoot "file-artifact.txt"
"WinST/DT benign validation $(Get-Date -Format o)" | Set-Content -Path $filePath -Encoding UTF8
Remove-Item -Path $filePath -Force

$regPath = "HKCU:\Software\WinSTDT\BenignValidation"
New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name "ValidationValue" -Value "created"
Remove-ItemProperty -Path $regPath -Name "ValidationValue" -Force
Remove-Item -Path $regPath -Force

try {
    Resolve-DnsName -Name $DnsName -ErrorAction Stop | Out-Null
} catch {
    Write-Warning "DNS lookup degraded: $($_.Exception.Message)"
}

try {
    Invoke-WebRequest -Uri $EgressUrl -UseBasicParsing -TimeoutSec 10 | Out-Null
} catch {
    Write-Warning "HTTP simulated egress degraded: $($_.Exception.Message)"
}

@{
    schema_version = "1.0"
    child_process_exit_code = $child.ExitCode
    file_operation = "create_write_delete"
    registry_operation = "set_delete"
    dns_name = $DnsName
    egress_url = $EgressUrl
    completed_at_utc = (Get-Date).ToUniversalTime().ToString("o")
} | ConvertTo-Json -Depth 4
