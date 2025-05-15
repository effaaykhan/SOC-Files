# -----------------------------------------
# CyberSentinel (Wazuh) Windows Agent Installer Script
# -----------------------------------------
# Run this script as Administrator in PowerShell.

# 1. Set variables for download URL and manager IP
$installerUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.2-1.msi"
$managerIP = "192.168.1.69"
$installerPath = "$env:TEMP\wazuh-agent-4.11.2-1.msi"

Write-Host "Downloading CyberSentinel agent installer..."
Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath

# 2. Install the agent silently and register with the manager
Write-Host "Installing CyberSentinel agent (this may take a moment)..."
$msiArgs = "/i `"$installerPath`" /qn WAZUH_MANAGER=`"$managerIP`""
Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -NoNewWindow

# 3. Determine the installation directory (default is under Program Files)
if (Test-Path "C:\Program Files (x86)\ossec-agent") {
    $installPath = "C:\Program Files (x86)\ossec-agent"
} elseif (Test-Path "C:\Program Files\ossec-agent") {
    $installPath = "C:\Program Files\ossec-agent"
} else {
    Write-Error "Installation directory not found. Exiting."
    exit 1
}

# 4. Download and replace the agent configuration file
Write-Host "Configuring CyberSentinel agent..."
$configUrl = "https://raw.githubusercontent.com/effaaykhan/SOC-Files/main/Wazuh/windows-agent.conf"
$configPath = Join-Path $installPath "ossec.conf"
# (Optional) Back up the original config:
Copy-Item -Path $configPath -Destination "${configPath}.backup" -ErrorAction SilentlyContinue
# Download the new configuration
Invoke-WebRequest -Uri $configUrl -OutFile $configPath

# 5. Apply audit policy settings as specified
Write-Host "Applying audit policy settings..."
# Enable auditing for Removable Storage, Plug and Play, and File System
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable
# Enable the Microsoft-Windows-DriverFrameworks-UserMode log
wevtutil set-log "Microsoft-Windows-DriverFrameworks-UserMode/Operational" /enabled:true

# 6. Rename the service display name to "CyberSentinel Agent" (hides "Wazuh" name)
Write-Host "Renaming service to CyberSentinel Agent..."
$service = Get-Service | Where-Object { $_.Name -like "wazuh*" }
if ($service) {
    $svcName = $service.Name
    sc.exe config $svcName DisplayName= "CyberSentinel Agent"
}

# 7. Start the agent service if not already running
Write-Host "Starting CyberSentinel agent service..."
Start-Service -Name $service.Name

Write-Host "CyberSentinel agent installation and configuration complete."
