# Define variables
$AgentUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.2-1.msi"
$AgentInstaller = "$env:TEMP\wazuh-agent.msi"
$ManagerIP = "192.168.1.69"
$ConfigUrl = "https://raw.githubusercontent.com/effaaykhan/SOC-Files/main/Wazuh/windows-agent.conf"
$ConfigDestination = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$DisplayServiceName = "CyberSentinel Agent"
$NewServiceDisplayName = "CyberSentinel Agent"

# Step 1: Download and Install Wazuh Agent
Invoke-WebRequest -Uri $AgentUrl -OutFile $AgentInstaller
Start-Process "msiexec.exe" -ArgumentList "/i `"$AgentInstaller`" /q WAZUH_MANAGER='$ManagerIP'" -Wait

# Step 2: Stop the agent service before replacing config
Stop-Service -Name "WazuhSvc" -Force

# Step 3: Download and Replace ossec.conf with custom version
Invoke-WebRequest -Uri $ConfigUrl -OutFile $ConfigDestination -UseBasicParsing

# Step 4: Change the display name of the service
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WazuhSvc" -Name "DisplayName" -Value $NewServiceDisplayName

# Step 5: Optional Cosmetic Changes
# Rename Program Group (Start Menu) if it exists
$programGroup = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Wazuh Agent"
if (Test-Path $programGroup) {
    Rename-Item -Path $programGroup -NewName "CyberSentinel Agent"
}

# Rename desktop shortcut if present
$desktopShortcut = "$env:Public\Desktop\Wazuh Agent.lnk"
if (Test-Path $desktopShortcut) {
    Rename-Item -Path $desktopShortcut -NewName "CyberSentinel Agent.lnk"
}

# Rename the installation folder (not safe if app is running)
$installPath = "C:\Program Files (x86)\ossec-agent"
$customPath = "C:\Program Files (x86)\CyberSentinel"
if (!(Test-Path $customPath)) {
    try {
        Move-Item -Path $installPath -Destination $customPath
    } catch {
        Write-Host "Could not rename folder while service is using it."
    }
}

# Step 6: Restart the agent
Start-Service -Name "WazuhSvc"
Write-Host "CyberSentinel Agent installed and configured."
