<#
.SYNOPSIS
    Installs the Wazuh agent on Windows with a custom service name "CyberSentinelAgent".
.DESCRIPTION
    This script downloads the latest stable 64-bit Wazuh agent MSI from the official packages site and installs it silently.
    It then replaces the default agent config, renames the service and UI labels, and starts the new service.
    Requires Administrator privileges.
#>

# Ensure the script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# Step 1: Define URLs and paths
# Latest Wazuh agent version (update as needed; 4.12.0 is current as of May 2025:contentReference[oaicite:11]{index=11})
$version = "4.12.0-1"
$msiName = "wazuh-agent-$version.msi"
$downloadDir = "$env:TEMP"
$msiPath = Join-Path $downloadDir $msiName

# Official download URL for the 64-bit Wazuh agent MSI:contentReference[oaicite:12]{index=12}
$msiUrl = "https://packages.wazuh.com/4.x/windows/$msiName"

Write-Host "Downloading Wazuh Agent MSI from $msiUrl..."
try {
    Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing
    Write-Host "Downloaded Wazuh agent installer to $msiPath"
} catch {
    Write-Error "Failed to download Wazuh MSI. $_"
    exit 1
}

# Step 2: Silent installation of the Wazuh agent via MSIEXEC:contentReference[oaicite:13]{index=13}
Write-Host "Installing Wazuh Agent silently..."
$msiArgs = "/i `"$msiPath`" /qn"
$proc = Start-Process -FilePath msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
if ($proc.ExitCode -ne 0) {
    Write-Error "Wazuh agent installation failed with exit code $($proc.ExitCode)."
    exit 1
}
Write-Host "Wazuh agent installed successfully."

# Step 3: Replace default ossec.conf with custom config
# Wazuh agent files are installed to "C:\Program Files (x86)\ossec-agent" by default:contentReference[oaicite:14]{index=14}
$ossecDir = "${env:ProgramFiles(x86)}\ossec-agent"
$configUrl = "https://raw.githubusercontent.com/effaaykhan/SOC-Files/main/Wazuh/windows-agent.conf"
$destConfig = Join-Path $ossecDir "ossec.conf"

if (Test-Path $ossecDir) {
    Write-Host "Stopping Wazuh agent service to replace configuration..."
    # Stop the service if running (service name is WazuhSvc by default:contentReference[oaicite:15]{index=15})
    try { Stop-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue } catch {}
    
    # Backup the original config (optional)
    if (Test-Path $destConfig) {
        Copy-Item $destConfig "$destConfig.bak" -Force
        Write-Host "Backup of original ossec.conf created."
    }
    # Download and overwrite the config file
    try {
        Invoke-WebRequest -Uri $configUrl -OutFile $destConfig -UseBasicParsing
        Write-Host "Replaced ossec.conf with custom configuration from $configUrl"
    } catch {
        Write-Error "Failed to download or replace ossec.conf. $_"
        exit 1
    }
} else {
    Write-Warning "Expected Wazuh installation folder not found: $ossecDir"
}

# Step 4: Rename Windows Service
# The default service name is "WazuhSvc":contentReference[oaicite:16]{index=16}. We delete it and create a new one.
Write-Host "Renaming Wazuh service to 'CyberSentinelAgent'..."
# Stop and remove old service if it exists
try {
    Stop-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    sc.exe delete "WazuhSvc" | Out-Null
    Write-Host "Original service 'WazuhSvc' stopped and deleted."
} catch {
    Write-Host "Service 'WazuhSvc' not found or already removed."
}

# Path to the Wazuh agent binary (unchanged):contentReference[oaicite:17]{index=17}:contentReference[oaicite:18]{index=18}
$agentExe = Join-Path $ossecDir "wazuh-agent.exe"
if (-not (Test-Path $agentExe)) {
    Write-Error "Wazuh agent executable not found at $agentExe"
    exit 1
}
# Create new service with DisplayName "CyberSentinel Agent"
$serviceName = "CyberSentinelAgent"
$displayName = "CyberSentinel Agent"
$binaryPath = "`"$agentExe`" -d"  # '-d' typically runs in daemon mode
$createArgs = "create $serviceName binPath= `$binaryPath` DisplayName= `$displayName` start= auto"
# Note: sc.exe requires exact spacing as shown
sc.exe $createArgs | Out-Null
Write-Host "Service '$serviceName' created (DisplayName='$displayName')."

# Step 5: Rename UI shortcuts from 'Wazuh' to 'CyberSentinel'
Write-Host "Renaming Start Menu and Desktop shortcuts from 'Wazuh' to 'CyberSentinel'..."
# Define locations for common Start Menu and Desktop shortcuts
$startMenuPaths = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
    "$env:AppData\Microsoft\Windows\Start Menu\Programs"
)
$desktopPaths = @(
    "$env:Public\Desktop",
    "$env:UserProfile\Desktop"
)
foreach ($path in $startMenuPaths + $desktopPaths) {
    if (Test-Path $path) {
        Get-ChildItem -Path $path -Filter "*Wazuh*.lnk" -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object {
            $newName = $_.Name -replace 'Wazuh','CyberSentinel'
            Rename-Item -Path $_.FullName -NewName $newName -ErrorAction SilentlyContinue
            Write-Host "Renamed shortcut '$($_.Name)' to '$newName'."
        }
    }
}

# Step 6: Update registry uninstall entries to new DisplayName
Write-Host "Updating registry uninstall entries to 'CyberSentinel Agent'..."
# Registry paths for uninstall entries (both 32-bit and 64-bit nodes)
$uninstallKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)
foreach ($root in $uninstallKeys) {
    Get-ChildItem -Path $root -ErrorAction SilentlyContinue |
    ForEach-Object {
        $displayNameValue = Get-ItemProperty -Path $_.PsPath -Name "DisplayName" -ErrorAction SilentlyContinue |
                             Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue
        if ($displayNameValue -and $displayNameValue -match "Wazuh") {
            Set-ItemProperty -Path $_.PsPath -Name "DisplayName" -Value "CyberSentinel Agent" -Force
            Write-Host "Updated registry DisplayName for '$($displayNameValue)' to 'CyberSentinel Agent'."
        }
    }
}

# Step 7: Start the new service and verify
Write-Host "Starting the CyberSentinelAgent service..."
Start-Service -Name $serviceName
Start-Sleep -Seconds 3  # give it a moment to start
$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-Host "Service '$serviceName' is running successfully."
} else {
    Write-Warning "Service '$serviceName' failed to start."
}

Write-Host "Wazuh agent installation and customization completed. The agent is now running as 'CyberSentinelAgent' (display name '$displayName')."
