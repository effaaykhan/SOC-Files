# Ensure script is run as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "You do not have Administrator rights to run this script! Please re-run as Administrator."
    exit 1
}

# Step 1: Download and install the CyberSentinel agent (Wazuh)
$wazuhManager = "192.168.1.69"
$agentVersion = "4.11.2-1"
$installerUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-${agentVersion}.msi"
$msiPath = "$env:TEMP\wazuh-agent-${agentVersion}.msi"

Invoke-WebRequest -Uri $installerUrl -OutFile $msiPath
Start-Process -FilePath msiexec.exe -ArgumentList "/i `"$msiPath`" /qn WAZUH_MANAGER=$wazuhManager" -Wait

# Step 2: Determine installation path
$installDir = "${env:ProgramFiles}\ossec-agent"
if (-Not (Test-Path $installDir)) {
    $installDir = "${env:ProgramFiles(x86)}\ossec-agent"
}
$configPath = Join-Path -Path $installDir -ChildPath "ossec.conf"

# Step 3: Download the custom ossec.conf (no modifications)
$rawConfigUrl = "https://raw.githubusercontent.com/firdouskhan000/CyberSentinel/main/ossec.conf"
$tempConfig = "$env:TEMP\ossec.conf"
Invoke-WebRequest -Uri $rawConfigUrl -OutFile $tempConfig

# Step 4: Replace the configuration file without modifications
Copy-Item -Path $tempConfig -Destination $configPath -Force

# Step 5: Configure Windows Audit Policies
AuditPol /set /subcategory:"Plug and Play Events" /success:enable /failure:enable
AuditPol /set /subcategory:"Removable Storage" /success:enable /failure:enable
AuditPol /set /subcategory:"File System" /success:enable /failure:enable

# Enable DriverFrameworks-UserMode/Operational log
wevtutil set-log Microsoft-Windows-DriverFrameworks-UserMode/Operational /enabled:true

# Step 6: Restart the CyberSentinel (Wazuh) service
Stop-Service -Name "WazuhSvc" -Force
Start-Service -Name "WazuhSvc"
Start-Sleep -Seconds 5
$service = Get-Service -Name "WazuhSvc"
if ($service.Status -eq "Running") {
    Write-Host "CyberSentinel agent service is running."
} else {
    Write-Warning "CyberSentinel agent service is not running."
}

# Step 7: Cleanup
Remove-Item -Path $msiPath -Force
Remove-Item -Path $tempConfig -Force

Write-Host "CyberSentinel agent deployment and configuration complete."
