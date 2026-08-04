[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AgentPath,
    [string]$PythonPath = 'C:\Python3\python.exe',
    [int]$Port = 8000
)

$ErrorActionPreference = 'Stop'
$runKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
$run = Get-ItemProperty -Path $runKey
$property = $run.PSObject.Properties |
    Where-Object {
        $_.Name -notmatch '^PS' -and
        ($_.Value -match "-port\s+$Port" -or $_.Value -match "agent\.py.*\s$Port$")
    } |
    Select-Object -First 1

if (-not $property) {
    throw "A persistent CAPE agent Run entry for port $Port was not found."
}

$command = "$PythonPath $AgentPath 0.0.0.0 $Port"
Set-ItemProperty -Path $runKey -Name $property.Name -Value $command
Write-Output "Updated persistent CAPE agent entry '$($property.Name)'."
