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

    # Ensure root exists
    if (-not $xml.ossec_config) {
        throw "ossec_config root element not found in configuration."
    }

    # --- Server section ---
    $server = $xml.ossec_config.server
    if (-not $server) {
        $server = $xml.CreateElement("server")
        $xml.ossec_config.AppendChild($server) | Out-Null
    }
    $address = $server.address
    if (-not $address) {
        $address = $xml.CreateElement("address")
        $server.AppendChild($address) | Out-Null
    }
    $address.InnerText = $wazuhManager

    # --- Enrollment section ---
    $enrollment = $xml.ossec_config.enrollment
    if (-not $enrollment) {
        $enrollment = $xml.CreateElement("enrollment")
        $xml.ossec_config.AppendChild($enrollment) | Out-Null
    }

    $agentName = $env:COMPUTERNAME

    $agentNode = $enrollment.agent_name
    if (-not $agentNode) {
        $agentNode = $xml.CreateElement("agent_name")
        $enrollment.AppendChild($agentNode) | Out-Null
    }
    $agentNode.InnerText = $agentName

    $osCaption = (Get-CimInstance Win32_OperatingSystem).Caption
    if ($osCaption -match 'Windows\s+(\d+)') {
        $windowsGroup = "windows$($Matches[1])"
    } else {
        $windowsGroup = $osCaption.ToLower().Replace(' ', '')
    }

    $groupsNode = $enrollment.groups
    if (-not $groupsNode) {
        $groupsNode = $xml.CreateElement("groups")
        $enrollment.AppendChild($groupsNode) | Out-Null
    }
    $groupsNode.InnerText = $windowsGroup

    # --- Syscheck section ---
    $syscheck = $xml.ossec_config.syscheck
    if (-not $syscheck) {
        $syscheck = $xml.CreateElement("syscheck")
        $xml.ossec_config.AppendChild($syscheck) | Out-Null
    }

    # Remove existing <directories>
    $existingDirs = @($syscheck.SelectNodes("directories"))
    foreach ($dir in $existingDirs) {
        $syscheck.RemoveChild($dir) | Out-Null
    }

    $desktopDir = [Environment]::GetFolderPath("Desktop")
    $downloadsDir = Join-Path ([Environment]::GetFolderPath("UserProfile")) 'Downloads'

    foreach ($path in @($desktopDir, $downloadsDir)) {
        $dirNode = $xml.CreateElement("directories")
        $dirNode.InnerText = $path
        $dirNode.SetAttribute("check_all", "yes")
        $dirNode.SetAttribute("realtime", "yes")
        $syscheck.AppendChild($dirNode) | Out-Null
    }

    # Save and replace config
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
