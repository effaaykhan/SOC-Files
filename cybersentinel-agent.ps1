# 1. Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
        [Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Warning "This script must be run as Administrator."
    Exit 1
}

# 2. Define variables for version, manager IP, and installer paths
$wazuhVersion = "4.11.2-1"
$wazuhManager = "192.168.1.69"
$installerUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$wazuhVersion.msi"
$installerPath = Join-Path $env:TEMP "wazuh-agent-$wazuhVersion.msi"

# 3. Download the Wazuh agent installer from the official repository
Write-Host "Downloading Cybersentinel agent version $wazuhVersion..."
Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath

# 4. Install the agent silently with the specified manager IP
Write-Host "Installing Cybersentinel agent..."
$msiArgs = "/i `"$installerPath`" /qn WAZUH_MANAGER=`"$wazuhManager`""
Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -NoNewWindow -Wait

# 5. Replace the default ossec.conf with custom configuration
# Determine the install directory (32-bit vs 64-bit)
if (Test-Path "$env:ProgramFiles(x86)\ossec-agent") {
    $installDir = "$env:ProgramFiles(x86)\ossec-agent"
} else {
    $installDir = "$env:ProgramFiles\ossec-agent"
}
$configPath = Join-Path $installDir "ossec.conf"

# Remove existing config if present
if (Test-Path $configPath) {
    Remove-Item -Path $configPath -Force
}

# Download custom ossec.conf from GitHub
Write-Host "Downloading custom ossec.conf configuration..."
$customConfigUrl = "https://raw.githubusercontent.com/effaaykhan/SOC-Files/main/Wazuh/windows-agent.conf"
Invoke-WebRequest -Uri $customConfigUrl -OutFile $configPath

# 6. Enable Windows audit policies for Plug and Play, Removable Storage, and File System
Write-Host "Configuring Windows audit policies..."
auditpol /set /subcategory:"Plug and Play Events"   /success:enable /failure:enable
auditpol /set /subcategory:"Removable Storage"      /success:enable /failure:enable
auditpol /set /subcategory:"File System"           /success:enable /failure:enable

# 7. Enable the Microsoft-Windows-DriverFrameworks-UserMode/Operational event log
Write-Host "Enabling Microsoft-Windows-DriverFrameworks-UserMode/Operational log..."
wevtutil.exe sl "Microsoft-Windows-DriverFrameworks-UserMode/Operational" /e:true

# 8. Restart the Wazuh service to apply changes
$service = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
if ($service -ne $null) {
    Write-Host "Restarting Wazuh service..."
    Restart-Service -Name WazuhSvc -Force
}

# 9. Cleanup temporary files
Write-Host "Cleaning up temporary files..."
if (Test-Path $installerPath) {
    Remove-Item -Path $installerPath -Force
}

Write-Host "Cybersentinel agent installation and configuration completed successfully."
