# Requires Admin privileges and Windows PowerShell (run as Administrator)

# 1. Check for Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# 2. Download and Install CyberSentinel agent (Wazuh agent 4.11.2-1)
Write-Host "Downloading CyberSentinel agent installer..."
$msiUrl  = 'https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.2-1.msi'
$msiPath = Join-Path $env:TEMP 'CyberSentinel-agent.msi'
if (Test-Path $msiPath) { Remove-Item $msiPath -Force }
Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath

Write-Host "Installing CyberSentinel agent..."
Start-Process -FilePath msiexec.exe -ArgumentList '/i', $msiPath, '/qn', 'WAZUH_MANAGER="192.168.1.69"' -Wait -NoNewWindow

# 3. Wait for the installation directory (64-bit default)
$installDir = "${env:ProgramFiles(x86)}\ossec-agent"
$maxWaitSec = 60; $waitSec = 0
Write-Host "Waiting for installation directory to appear..."
while (-not (Test-Path $installDir) -and ($waitSec -lt $maxWaitSec)) {
    Start-Sleep -Seconds 1
    $waitSec++
}
if (-not (Test-Path $installDir)) {
    Write-Error "Installation directory '$installDir' not found after waiting."
    exit 1
}
Write-Host "Installation directory found at $installDir"

# 4. Download and replace the configuration file
Write-Host "Applying custom configuration..."
$configUrl  = 'https://raw.githubusercontent.com/effaaykhan/SOC-Files/main/Wazuh/windows-agent.conf'
$configTemp = Join-Path $env:TEMP 'windows-agent.conf'
if (Test-Path $configTemp) { Remove-Item $configTemp -Force }
Invoke-WebRequest -Uri $configUrl -OutFile $configTemp

$configDest = Join-Path $installDir 'ossec.conf'
Copy-Item -Path $configTemp -Destination $configDest -Force
Remove-Item $configTemp -Force

# 5. Enable Windows audit policy (Plug and Play, Removable Storage, File System)
Write-Host "Enabling audit for Plug and Play Events, Removable Storage, and File System..."
$auditCmd = '/set /subcategory:"Plug and Play Events","Removable Storage","File System" /success:enable /failure:enable'
Start-Process auditpol.exe -ArgumentList $auditCmd -Wait -NoNewWindow

# 6. Enable the Microsoft-DriverFrameworks-UserMode/Operational log
Write-Host "Enabling Microsoft-Windows-DriverFrameworks-UserMode/Operational log..."
wevtutil sl "Microsoft-Windows-DriverFrameworks-UserMode/Operational" /e:true

# 7. Restart the CyberSentinel (WazuhSvc) service
Write-Host "Restarting CyberSentinel agent service..."
Restart-Service -Name WazuhSvc -Force -ErrorAction Stop

# 8. Clean up temp files
Write-Host "Cleaning up temporary files..."
if (Test-Path $msiPath) { Remove-Item $msiPath -Force }

Write-Host "CyberSentinel agent installation and configuration complete."
