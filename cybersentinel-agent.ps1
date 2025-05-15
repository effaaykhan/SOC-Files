# Variables
$wazuhUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.2-1.msi"
$customConfUrl = "https://raw.githubusercontent.com/effaaykhan/SOC-Files/main/Wazuh/windows-agent.conf"
$tmpInstaller = "$env:TEMP\wazuh-agent.msi"
$tmpConfFile = "$env:TEMP\ossec.conf"
$confDestination = "C:\Program Files (x86)\ossec-agent\ossec.conf"

# Prompt user for agent name
$agentName = Read-Host "Enter a unique agent name for this machine"

# Step 1: Download the Wazuh Agent installer
Invoke-WebRequest -Uri $wazuhUrl -OutFile $tmpInstaller

# Step 2: Install Wazuh Agent silently
Start-Process -Wait msiexec.exe -ArgumentList "/i `"$tmpInstaller`" /q WAZUH_MANAGER='192.168.1.69' WAZUH_AGENT_GROUP='windows'"

# Wait a moment for the installation to complete
Start-Sleep -Seconds 10

# Step 3: Download custom ossec.conf from GitHub
Invoke-WebRequest -Uri $customConfUrl -OutFile $tmpConfFile -UseBasicParsing

# Step 4: Insert the agent name into the ossec.conf
[xml]$xml = Get-Content $tmpConfFile
$agentNameNode = $xml.ossec_config.client.enrollment.agent_name
if ($agentNameNode) {
    $agentNameNode.InnerText = $agentName
} else {
    # If <agent_name> doesn't exist, add it manually
    $enrollmentNode = $xml.ossec_config.client.enrollment
    $newNode = $xml.CreateElement("agent_name")
    $newNode.InnerText = $agentName
    $enrollmentNode.AppendChild($newNode) | Out-Null
}
$xml.Save($confDestination)

# Step 5: Rename the Wazuh service display name to "CyberSentinel Agent"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WazuhSvc" -Name "DisplayName" -Value "CyberSentinel Agent"

# Step 6: Restart the Wazuh service (now will appear as "CyberSentinel Agent")
Restart-Service -Name WazuhSvc

# Optional: Confirm the rename
Write-Host "`n[+] CyberSentinel agent installation complete with Agent Name: $agentName" -ForegroundColor Green
