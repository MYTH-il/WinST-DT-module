[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$removePaths = @(
    'C:\ProgramData\WinSTDT\Install-CapeAgent.ps1',
    'C:\ProgramData\WinSTDT\Invoke-GuestHardening.ps1',
    'C:\ProgramData\WinSTDT\Sanitize-GoldenImage.ps1',
    'C:\ProgramData\WinSTDT\guest-hardening.config.json',
    'C:\ProgramData\WinSTDT\vc_redist.x64.exe',
    'C:\ProgramData\WinSTDT\validation',
    'C:\ProgramData\WinSTDT\behavior\trace.etl',
    'C:\ProgramData\WinSTDT\behavior\telemetry.json',
    'C:\ProgramData\WinSTDT\behavior\etw_state.json',
    'C:\Windows\Temp\winstdt-anti-evasion',
    'C:\Windows\Temp\winstdt-cape-agent'
)

foreach ($path in $removePaths) {
    Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
}

Get-ChildItem 'C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt' -Force -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue

Write-Output 'Golden image setup and validation residue sanitized.'
