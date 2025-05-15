<#
  ____                 _               ____             _   _ _       
 / ___|  ___ _ __ ___ (_)_ __   __ _  / ___|  ___ _ __(_)_(_) |_ ___ 
 \___ \ / _ \ '_ ` _ \| | '_ \ / _` | \___ \ / __| '__| | | | __/ _ \
  ___) |  __/ | | | | | | | | | (_| |  ___) | (__| |  | | | | ||  __/
 |____/ \___|_| |_| |_|_|_| |_|\__, | |____/ \___|_|  |_|_|_|\__\___|
                                |___/                              
CyberSentinel Agent - Wazuh Agent Rebranding Script
#>

# Enable verbose output
$VerbosePreference = "Continue"

function Write-Info { param($Message); Write-Host "[*] $Message" }
function Write-Warn { param($Message); Write-Warning "[!] $Message" }

# 1. Download and install the Wazuh agent silently
Write-Info "Downloading Wazuh Agent installer..."
$installerUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.2-1.msi"
$tempInstaller = "$env:TEMP\wazuh-agent-4.11.2-1.msi"
try {
    Invoke-WebRequest -Uri $installerUrl -OutFile $tempInstaller -UseBasicParsing -ErrorAction Stop
    Write-Info "Downloaded Wazuh Agent installer to $tempInstaller"
} catch {
    Write-Warn "Failed to download Wazuh Agent installer: $_"
}

Write-Info "Installing Wazuh Agent silently..."
try {
    Start-Process msiexec.exe -ArgumentList "/i `"$tempInstaller`"", "/qn", "/norestart" -Wait -ErrorAction Stop
    Write-Info "Wazuh Agent installed successfully."
} catch {
    Write-Warn "Wazuh Agent installation failed: $_"
}

# 2. Replace default ossec.conf with custom configuration
Write-Info "Applying custom ossec.conf configuration..."
$installPath = ""
if (Test-Path "$env:ProgramFiles(x86)\ossec-agent\ossec.conf") {
    $installPath = "$env:ProgramFiles(x86)\ossec-agent"
} elseif (Test-Path "$env:ProgramFiles\ossec-agent\ossec.conf") {
    $installPath = "$env:ProgramFiles\ossec-agent"
}
if ($installPath) {
    $ossecConf = Join-Path $installPath "ossec.conf"
    $customConfUrl = "https://raw.githubusercontent.com/effaaykhan/SOC-Files/main/Wazuh/windows-agent.conf"
    try {
        if (Test-Path $ossecConf) {
            Remove-Item $ossecConf -Force
        }
        Invoke-WebRequest -Uri $customConfUrl -OutFile $ossecConf -UseBasicParsing -ErrorAction Stop
        Write-Info "ossec.conf replaced with custom configuration."
    } catch {
        Write-Warn "Failed to apply custom ossec.conf: $_"
    }
} else {
    Write-Warn "Wazuh Agent installation directory not found. Skipping ossec.conf replacement."
}

# 3. Change the service display name to "CyberSentinel Agent"
Write-Info "Updating Windows service display name..."
$serviceName = "WazuhSvc"
try {
    Set-Service -Name $serviceName -DisplayName "CyberSentinel Agent" -ErrorAction Stop
    Write-Info "Service display name updated to 'CyberSentinel Agent'."
} catch {
    Write-Warn "Service '$serviceName' not found or display name could not be changed: $_"
}

# 4. Rename Start Menu folder and desktop shortcut
Write-Info "Renaming Start Menu and Desktop shortcuts..."
$programsPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
$wazuhFolder = Join-Path $programsPath "Wazuh Agent"
if (Test-Path $wazuhFolder) {
    try {
        Rename-Item -Path $wazuhFolder -NewName "CyberSentinel Agent"
        Write-Info "Start Menu folder renamed to 'CyberSentinel Agent'."
    } catch {
        Write-Warn "Failed to rename Start Menu folder: $_"
    }
} else {
    Write-Warn "Start Menu folder 'Wazuh Agent' not found."
}

# Public Desktop shortcut
$publicDesktop = [Environment]::GetFolderPath("CommonDesktopDirectory")
$shortcutPath = Join-Path $publicDesktop "Wazuh Agent.lnk"
if (Test-Path $shortcutPath) {
    try {
        Rename-Item -Path $shortcutPath -NewName "CyberSentinel Agent.lnk"
        Write-Info "Public desktop shortcut renamed to 'CyberSentinel Agent.lnk'."
    } catch {
        Write-Warn "Failed to rename public desktop shortcut: $_"
    }
} else {
    Write-Warn "Public desktop shortcut 'Wazuh Agent.lnk' not found."
}

# Current user Desktop shortcut
$userDesktop = [Environment]::GetFolderPath("Desktop")
$shortcutPathUser = Join-Path $userDesktop "Wazuh Agent.lnk"
if (Test-Path $shortcutPathUser) {
    try {
        Rename-Item -Path $shortcutPathUser -NewName "CyberSentinel Agent.lnk"
        Write-Info "User desktop shortcut renamed to 'CyberSentinel Agent.lnk'."
    } catch {
        Write-Warn "Failed to rename user desktop shortcut: $_"
    }
} else {
    Write-Warn "User desktop shortcut 'Wazuh Agent.lnk' not found."
}

Write-Info "Rebranding complete."
