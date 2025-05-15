# PowerShell script to install CyberSentinel (Wazuh-based) Agent on Windows
# Requirements:
# - Run as Administrator
# - Ensure execution policy allows running scripts or sign this script.

# Define variables
$wazuhManager = "192.168.1.69"  # Wazuh manager IP
$installerUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.12.0-1.msi"  # URL to Wazuh agent installer (update if necessary)
$customConfigUrl = "https://raw.githubusercontent.com/effaaykhan/SOC-Files/main/Wazuh/windows-agent.conf"  # URL to custom Wazuh agent config
$logFile = Join-Path $env:TEMP "CyberSentinelInstall.log"

# Function to log messages with timestamp
function Write-Log {
    param([string]$message)
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logEntry = "${timestamp} - ${message}"
    Write-Host $logEntry
    Add-Content -Path $logFile -Value $logEntry
}

# Remove existing log file if present
if (Test-Path $logFile) {
    Remove-Item $logFile -Force
}

# Check for administrative privileges
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Log "ERROR: Script is not running as Administrator. Exiting."
    exit 1
}

Write-Log "Starting CyberSentinel (Wazuh agent) installation..."

# Download the Wazuh agent installer
$installerPath = Join-Path $env:TEMP "wazuh-agent.msi"
try {
    Write-Log "Downloading Wazuh agent installer from $installerUrl..."
    Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing
    Write-Log "Downloaded Wazuh agent installer to $installerPath."
} catch {
    Write-Log "ERROR: Failed to download Wazuh agent installer. $_"
    exit 1
}

# Install the Wazuh agent silently
try {
    Write-Log "Installing Wazuh agent silently..."
    $msiArgs = "/i `"$installerPath`" /qn WAZUH_MANAGER=`"$wazuhManager`""
    Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -NoNewWindow
    Write-Log "Wazuh agent installation completed."
} catch {
    Write-Log "ERROR: Wazuh agent installation failed. $_"
    exit 1
}

# Determine Wazuh agent installation directory based on architecture
if (Test-Path "$env:ProgramFiles (x86)\ossec-agent") {
    $installDir = "$env:ProgramFiles (x86)\ossec-agent"
} elseif (Test-Path "$env:ProgramFiles\ossec-agent") {
    $installDir = "$env:ProgramFiles\ossec-agent"
} else {
    Write-Log "ERROR: Wazuh agent installation directory not found."
    exit 1
}

# Replace the default configuration with custom config
$agentConfigPath = Join-Path $installDir "ossec.conf"
if (Test-Path $agentConfigPath) {
    # Backup original config
    Copy-Item -Path $agentConfigPath -Destination "${agentConfigPath}.bak" -Force
    Write-Log "Backed up original config to ${agentConfigPath}.bak"
}
try {
    Write-Log "Downloading custom agent config from $customConfigUrl..."
    Invoke-WebRequest -Uri $customConfigUrl -OutFile "$env:TEMP\windows-agent.conf" -UseBasicParsing
    Move-Item -Path "$env:TEMP\windows-agent.conf" -Destination $agentConfigPath -Force
    Write-Log "Replaced agent configuration with custom config."
} catch {
    Write-Log "ERROR: Failed to download or replace agent config. $_"
    exit 1
}

# Apply required audit policy settings
Write-Log "Applying audit policy settings..."
try {
    & auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
    & auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:enable
    & auditpol /set /subcategory:"File System" /success:enable /failure:enable
    & wevtutil set-log "Microsoft-Windows-DriverFrameworks-UserMode/Operational" /enabled:true
    Write-Log "Audit policy settings applied successfully."
} catch {
    Write-Log "ERROR: Failed to apply some audit policy settings. $_"
}

# Rename the Wazuh agent service display name without creating a new service
Write-Log "Renaming Wazuh agent service display name to 'CyberSentinel Agent'..."
try {
    $svc = Get-WmiObject -Class Win32_Service -Filter "Name='WazuhSvc'"
    if ($svc) {
        $result = $svc.Change("CyberSentinel Agent", $svc.PathName, [uint32]$svc.ServiceType, [uint32]$svc.ErrorControl, $svc.StartMode, $svc.DesktopInteract, $svc.StartName, $svc.StartPassword, $svc.LoadOrderGroup, $svc.LoadOrderGroupDependencies, $svc.ServiceDependencies)
        if ($result.ReturnValue -eq 0) {
            Write-Log "Service display name changed successfully."
        } else {
            Write-Log "WARNING: Could not change service display name. WMI return code: $($result.ReturnValue)"
        }
    } else {
        Write-Log "WARNING: Wazuh service not found. Skipping display name change."
    }
} catch {
    Write-Log "ERROR: Exception while renaming service display name. $_"
}

# Validate that the agent service is installed and running
Write-Log "Validating Wazuh agent service status..."
try {
    $service = Get-Service -Name WazuhSvc -ErrorAction Stop
    if ($service.Status -eq 'Running') {
        Write-Log "Wazuh agent service is running."
    } else {
        Write-Log "Wazuh agent service is installed but not running. Attempting to start it..."
        Start-Service -Name WazuhSvc
        Start-Sleep -Seconds 5
        if ((Get-Service -Name WazuhSvc).Status -eq 'Running') {
            Write-Log "Wazuh agent service started successfully."
        } else {
            Write-Log "ERROR: Failed to start Wazuh agent service."
        }
    }
} catch {
    Write-Log "ERROR: Wazuh agent service is not installed or cannot be accessed. $_"
}

Write-Log "CyberSentinel agent installation and configuration completed."
