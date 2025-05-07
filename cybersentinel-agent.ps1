# Requires administrator privileges

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

# --- Step 1: Download and install CyberSentinel agent silently ---
$wazuhManager = "192.168.1.69" 
$agentVersion = "4.11.2-1"
$installerUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$agentVersion.msi"
$msiPath = Join-Path $env:TEMP "wazuh-agent-$agentVersion.msi"

try {
    Write-Host "Downloading CyberSentinel agent MSI installer..."
    Invoke-WebRequest -Uri $installerUrl -OutFile $msiPath -ErrorAction Stop

    Write-Host "Installing CyberSentinel agent silently..."
    $installProcess = Start-Process -FilePath msiexec.exe -ArgumentList "/i `"$msiPath`" /qn WAZUH_MANAGER=`"$wazuhManager`"" -Wait -PassThru

    if ($installProcess.ExitCode -ne 0) {
        Write-Error "Installation failed with exit code $($installProcess.ExitCode)"
        exit 1
    }
} catch {
    Write-Error "Error during download or installation: $_"
    exit 1
}

# --- Step 2: Determine install directory for ossec.conf ---
$pfX86 = ${Env:ProgramFiles(x86)}
if ($pfX86 -and (Test-Path (Join-Path $pfX86 'ossec-agent'))) {
    $installDir = Join-Path $pfX86 'ossec-agent'
} else {
    $installDir = Join-Path $env:ProgramFiles 'ossec-agent'
}
$configPath = Join-Path $installDir 'ossec.conf'

if (-not (Test-Path $installDir)) {
    Write-Error "CyberSentinel agent installation directory not found at $installDir"
    exit 1
}

# --- Step 3: Download custom ossec.conf from GitHub ---
$rawConfigUrl = "https://raw.githubusercontent.com/effaaykhan/SOC-Files/main/Wazuh/ossec.conf"
$tempConfig = Join-Path $env:TEMP "ossec.conf"

try {
    Write-Host "Downloading custom CyberSentinel configuration from GitHub..."
    Invoke-WebRequest -Uri $rawConfigUrl -OutFile $tempConfig -ErrorAction Stop
} catch {
    Write-Error "Failed to download custom configuration: $_"
    exit 1
}

# Backup original config
$backupConfig = Join-Path $env:TEMP "ossec.conf.backup"
if (Test-Path $configPath) {
    Copy-Item -Path $configPath -Destination $backupConfig -Force
    Write-Host "Original configuration backed up to $backupConfig"
}

# --- Step 4: Modify ossec.conf XML settings ---
try {
    [xml]$xml = Get-Content $tempConfig

    # 4a: Set <address> under <server> to the Wazuh manager IP
    $xml.ossec_config.server.address = $wazuhManager

    # 4b: Set <agent_name> under <enrollment> to this machine's hostname
    $agentName = $env:COMPUTERNAME
    $xml.ossec_config.enrollment.agent_name = $agentName

    # 4c: Set <groups> under <enrollment> to the Windows major version (e.g. "windows10")
    $osCaption = (Get-CimInstance Win32_OperatingSystem).Caption
    if ($osCaption -match 'Windows\s+(\d+)') {
        $windowsGroup = "windows$($Matches[1])"
    } else {
        $windowsGroup = $osCaption.ToLower().Replace(' ', '')
    }
    $xml.ossec_config.enrollment.groups = $windowsGroup

    # 4d: Set <directories> under <syscheck> to user Desktop and Downloads folders
    $desktopDir = [Environment]::GetFolderPath("Desktop")
    $userProfile = [Environment]::GetFolderPath("UserProfile")
    $downloadsDir = Join-Path $userProfile 'Downloads'
    $syscheck = $xml.ossec_config.syscheck

    # Remove existing directories elements
    $existingDirs = @($syscheck.SelectNodes("directories"))
    foreach ($dir in $existingDirs) {
        $syscheck.RemoveChild($dir) | Out-Null
    }

    # Add Desktop directory
    $desktopDirNode = $xml.CreateElement("directories")
    $desktopDirNode.InnerText = $desktopDir
    $desktopDirNode.SetAttribute("check_all", "yes")
    $desktopDirNode.SetAttribute("realtime", "yes")
    $syscheck.AppendChild($desktopDirNode) | Out-Null

    # Add Downloads directory
    $downloadsDirNode = $xml.CreateElement("directories")
    $downloadsDirNode.InnerText = $downloadsDir
    $downloadsDirNode.SetAttribute("check_all", "yes")
    $downloadsDirNode.SetAttribute("realtime", "yes")
    $syscheck.AppendChild($downloadsDirNode) | Out-Null

    # Save the modified config and move it to the agent directory
    Write-Host "Applying modified CyberSentinel configuration..."
    $xml.Save($tempConfig)
    Move-Item -Path $tempConfig -Destination $configPath -Force
} catch {
    Write-Error "Error modifying configuration: $_"
    if (Test-Path $backupConfig) {
        Move-Item -Path $backupConfig -Destination $configPath -Force
        Write-Host "Restored original configuration from backup"
    }
    exit 1
}

# --- Step 5: Apply Windows audit policy changes ---
try {
    Write-Host "Configuring Windows audit policies for CyberSentinel..."
    AuditPol /set /subcategory:"Plug and Play Events" /success:enable /failure:enable
    AuditPol /set /subcategory:"Removable Storage" /success:enable /failure:enable
    AuditPol /set /subcategory:"File System" /success:enable /failure:enable

    wevtutil set-log "Microsoft-Windows-DriverFrameworks-UserMode/Operational" /enabled:true
    Write-Host "Audit policies configured successfully."
} catch {
    Write-Warning "Error configuring audit policies: $_. Continuing with installation."
}

# --- Step 6: Restart the CyberSentinel agent service ---
try {
    Write-Host "Restarting CyberSentinel agent service..."
    if (Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue) {
        Stop-Service -Name "WazuhSvc" -Force -ErrorAction Stop
        Start-Sleep -Seconds 2
        Start-Service -Name "WazuhSvc" -ErrorAction Stop

        $svcStatus = (Get-Service -Name "WazuhSvc").Status
        if ($svcStatus -eq "Running") {
            Write-Host "CyberSentinel agent service restarted successfully."
        } else {
            Write-Warning "CyberSentinel agent service is not running. Status: $svcStatus"
        }
    } else {
        Write-Error "CyberSentinel agent service (WazuhSvc) not found."
    }
} catch {
    Write-Error "Failed to restart CyberSentinel agent service: $_"
}

# --- Step 7: Cleanup temporary files ---
try {
    if (Test-Path $msiPath) {
        Remove-Item -Path $msiPath -Force
    }
    if (Test-Path $backupConfig) {
        Remove-Item -Path $backupConfig -Force
    }
    Write-Host "Temporary files cleaned up."
} catch {
    Write-Warning "Error cleaning up temporary files: $_"
}

Write-Host "CyberSentinel agent deployment and configuration complete."
