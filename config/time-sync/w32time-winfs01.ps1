<#
.SYNOPSIS
  Points WIN-FS01's Windows Time service at SIEM-01 (192.168.56.10) and
  forces UTC display, so Sysmon/Defender/Security event timestamps line up
  with the Linux hosts' chrony time for incident-timeline reconstruction.

  Run as Administrator.
#>

$ntpSource = "192.168.56.10"

Write-Host "[*] Configuring w32time to use $ntpSource as the NTP source..."
w32tm /config /manualpeerlist:"$ntpSource,0x8" /syncfromflags:manual /reliable:yes /update

Write-Host "[*] Restarting Windows Time service..."
Stop-Service w32time
Start-Service w32time

Write-Host "[*] Forcing an immediate resync..."
w32tm /resync /force

Write-Host "[*] Current status:"
w32tm /query /status

Write-Host "[*] Setting the system timezone to UTC for consistency with the Linux hosts..."
Set-TimeZone -Id "UTC"
Get-TimeZone
