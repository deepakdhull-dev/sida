<#
.SYNOPSIS
  Installs Sysinternals Sysmon on WIN-FS01 using the lab config
  (sysmonconfig.xml) that enables only the event types this project needs:
  Process Create (1), Network Connection (3), File Create (11).

  Run as Administrator. Requires internet access (NAT adapter) for the
  initial download — disable NAT again before running simulations.
#>

$ErrorActionPreference = "Stop"
$workDir = "C:\Lab\Sysmon"
New-Item -ItemType Directory -Path $workDir -Force | Out-Null

Write-Host "[*] Downloading Sysmon..."
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$workDir\Sysmon.zip"

Write-Host "[*] Extracting..."
Expand-Archive -Path "$workDir\Sysmon.zip" -DestinationPath $workDir -Force

Write-Host "[*] Copying lab config..."
Copy-Item -Path (Join-Path $PSScriptRoot "sysmonconfig.xml") -Destination "$workDir\sysmonconfig.xml" -Force

Write-Host "[*] Installing Sysmon with the lab config..."
& "$workDir\Sysmon64.exe" -accepteula -i "$workDir\sysmonconfig.xml"

Write-Host "[*] Verifying service state..."
Get-Service Sysmon64

Write-Host "[*] Done. Events will appear under: Microsoft-Windows-Sysmon/Operational"
