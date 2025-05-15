# Define Variables
$agentUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.2-1.msi"
$agentInstaller = "$env:TEMP\cybersentinel-agent.msi"
$configUrl = "https://raw.githubusercontent.com/YOUR_GITHUB_USERNAME/YOUR_REPO/main/ossec.conf"  # Change this to your actual config file
$configDest = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$wazuhManager = "192.168.1.69"

# Download Wazuh Agent
Invoke-WebRequest -Uri $agentUrl -OutFile $agentInstaller

# Install Wazuh Agent silently and point to your SIEM
Start-Process msiexec.exe -Wait -ArgumentList "/i `"$agentInstaller`" /q WAZUH_MANAGER='$wazuhManager'"

# Wait for install to complete and service to be installed
Start-Sleep -Seconds 10

# Download custom config
Invoke-WebRequest -Uri $configUrl -OutFile $configDest

# Set permissions if needed
icacls $configDest /grant "NT AUTHORITY\SYSTEM:F" /T

# Restart Wazuh Agent service
Restart-Service -Name "WazuhAgent"

Write-Host "CyberSentinel Agent installed and configured successfully."
