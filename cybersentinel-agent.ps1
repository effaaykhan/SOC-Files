# CyberSentinel Agent Installation Script
# =======================================
# Rebrands Wazuh agent with CyberSentinel name and replaces configuration

# Banner
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "      ____      _               _        " -ForegroundColor Cyan
Write-Host "     / ___|   _| |__  _ __ ___ (_)_ __   " -ForegroundColor Cyan
Write-Host "    | | | | | | '_ \| '_ ` _ \| | '_ \  " -ForegroundColor Cyan
Write-Host "    | |_| |_| | |_) | | | | | | | | | | " -ForegroundColor Cyan
Write-Host "     \____\__,_|_.__/|_| |_| |_|_|_| |_|" -ForegroundColor Cyan
Write-Host "         CyberSentinel Agent Installer " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# Variables
$AgentUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.2-1.msi"
$AgentInstaller = "$env:TEMP\wazuh-agent.msi"
$ManagerIP = "192.168.1.69"
$ConfigUrl = "https://raw.githubusercontent.com/effaaykhan/SOC-Files/main/Wazuh/windows-agent.conf"
$ConfigDestination = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$ServiceName = "WazuhSvc"
$NewDisplayName = "CyberSentinel Agent"

# Step 1: Download Wazuh Agent Installer
Write-Host "[*] Downloading Wazuh Agent installer..." -ForegroundColor Yellow
Invoke-WebRequest -Uri $AgentUrl -OutFile $AgentInstaller -UseBasicParsing
Write-Host "[+] Downloaded to $AgentInstaller" -ForegroundColor Green

# Step 2: Install Wazuh Agent Silently
Write-Host "[*] Installing Wazuh Agent..." -ForegroundColor Yellow
Start-Process "msiexec.exe" -ArgumentList "/i `"$AgentInstaller`" /q WAZUH_MANAGER='$ManagerIP'" -Wait
Write-Host "[+] Installation initiated." -ForegroundColor Green

# Step 3: Wait for the service to be registered
Write-Host "[*] Waiting for Wazuh service to appear..." -ForegroundColor Yellow
$attempt = 0
while ($attempt -lt 10 -and !(Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
    Start-Sleep -Seconds 2
    $attempt++
}
if (!(Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
    Write-Host "[!] Wazuh Service not found. Installation might have failed." -ForegroundColor Red
    exit 1
}
Write-Host "[+] Wazuh service is registered." -ForegroundColor Green

# Step 4: Stop the service before config replacement
Write-Host "[*] Stopping Wazuh Service..." -ForegroundColor Yellow
Stop-Service -Name $ServiceName -Force
Write-Host "[+] Service stopped." -ForegroundColor Green

# Step 5: Replace ossec.conf with custom configuration
Write-Host "[*] Replacing ossec.conf with CyberSentinel config..." -ForegroundColor Yellow
Invoke-WebRequest -Uri $ConfigUrl -OutFile $ConfigDestination -UseBasicParsing
Write-Host "[+] Configuration file replaced." -ForegroundColor Green

# Step 6: Rename service display name in registry
Write-Host "[*] Renaming service display name to 'CyberSentinel Agent'..." -ForegroundColor Yellow
try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name "DisplayName" -Value $NewDisplayName
    Write-Host "[+] Service display name updated." -ForegroundColor Green
} catch {
    Write-Host "[!] Could not change display name in registry. Run as Administrator." -ForegroundColor Red
}

# Step 7: Cosmetic changes (Start Menu, Desktop Shortcut)
Write-Host "[*] Performing cosmetic renaming..." -ForegroundColor Yellow

$programGroup = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Wazuh Agent"
if (Test-Path $programGroup) {
    Rename-Item -Path $programGroup -NewName "CyberSentinel Agent"
    Write-Host "[+] Renamed Start Menu entry." -ForegroundColor Green
}

$desktopShortcut = "$env:Public\Desktop\Wazuh Agent.lnk"
if (Test-Path $desktopShortcut) {
    Rename-Item -Path $desktopShortcut -NewName "CyberSentinel Agent.lnk"
    Write-Host "[+] Renamed desktop shortcut." -ForegroundColor Green
}

# Step 8: Start the service again
Write-Host "[*] Starting CyberSentinel Agent service..." -ForegroundColor Yellow
Start-Service -Name $ServiceName
Write-Host "[+] CyberSentinel Agent is now running." -ForegroundColor Green

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "[✓] CyberSentinel Agent installation complete." -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
