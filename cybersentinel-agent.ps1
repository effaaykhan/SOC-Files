# Step 1: Download and Install Wazuh Agent
$installerPath = "$env:TEMP\wazuh-agent.msi"
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.2-1.msi" -OutFile $installerPath

# Install silently and set Wazuh manager IP
Start-Process "msiexec.exe" -ArgumentList "/i `"$installerPath`" /qn WAZUH_MANAGER='192.168.1.69'" -Wait

# Wait a moment for service to register
Start-Sleep -Seconds 5

# Step 2: Cosmetic Rename — DisplayName and Description
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WazuhSvc" -Name "DisplayName" -Value "CyberSentinel Agent"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WazuhSvc" -Name "Description" -Value "CyberSentinel Agent for Security Monitoring"

# Step 3: Rename UI shortcuts
$paths = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
    "$env:Public\Desktop",
    "$env:UserProfile\Desktop"
)
foreach ($path in $paths) {
    if (Test-Path $path) {
        Get-ChildItem $path -Filter "*Wazuh*" -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object {
            $newName = $_.Name -replace 'Wazuh', 'CyberSentinel'
            Rename-Item -Path $_.FullName -NewName $newName -ErrorAction SilentlyContinue
        }
    }
}

# Step 4: Restart the service to apply
Restart-Service -Name "WazuhSvc"

Write-Host "`n✅ CyberSentinel Agent installed successfully'. Service is running.`n"
