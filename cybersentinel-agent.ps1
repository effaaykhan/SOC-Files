# Ensure running as administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# Variables
$wazuhVersion = "4.11.2-1"
$msiUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$wazuhVersion.msi"
$msiPath = Join-Path $env:TEMP "wazuh-agent-$wazuhVersion.msi"
$managerIP = "192.168.1.69"

# Download the Wazuh agent MSI
Write-Host "Downloading Wazuh Agent MSI from $msiUrl..."
try {
    Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing -ErrorAction Stop
    Write-Host "Downloaded: $msiPath"
} catch {
    Write-Error "Failed to download Wazuh MSI: $_"
    exit 1
}

# Install the Wazuh agent silently
Write-Host "Installing Wazuh Agent silently..."
try {
    $proc = Start-Process -FilePath msiexec.exe -ArgumentList '/i', $msiPath, '/qn', "WAZUH_MANAGER=$managerIP" `
            -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -ne 0) {
        Write-Error "Wazuh agent installation failed (exit code $($proc.ExitCode))."
        exit 1
    }
} catch {
    Write-Error "Installation error: $_"
    exit 1
}
Write-Host "Wazuh Agent installed successfully."

# Determine installation directory (64-bit vs 32-bit Windows)
if (Test-Path "$($env:ProgramFiles(x86))\ossec-agent") {
    $installDir = "$($env:ProgramFiles(x86))\ossec-agent"
} elseif (Test-Path "$($env:ProgramFiles)\ossec-agent") {
    $installDir = "$($env:ProgramFiles)\ossec-agent"
} else {
    Write-Error "Wazuh installation directory not found."
    exit 1
}
Write-Host "Wazuh Agent directory: $installDir"

# Stop the Wazuh service before updating config
Write-Host "Stopping Wazuh service..."
try {
    Stop-Service -Name WazuhSvc -ErrorAction Stop
} catch {
    Write-Warning "Wazuh service may not be running: $_"
}

# Download and replace ossec.conf
$confUrl = "https://raw.githubusercontent.com/effaaykhan/SOC-Files/main/Wazuh/windows-agent.conf"
$confPath = Join-Path $env:TEMP "windows-agent.conf"
Write-Host "Downloading replacement ossec.conf..."
try {
    Invoke-WebRequest -Uri $confUrl -OutFile $confPath -UseBasicParsing -ErrorAction Stop
} catch {
    Write-Error "Failed to download custom config: $_"
    exit 1
}

try {
    $destConf = Join-Path $installDir "ossec.conf"
    if (Test-Path $destConf) {
        Rename-Item -Path $destConf -NewName "ossec.conf.bak" -Force
        Write-Host "Backed up original ossec.conf to ossec.conf.bak"
    }
    Copy-Item -Path $confPath -Destination $destConf -Force
    Write-Host "Replaced ossec.conf with custom configuration."
} catch {
    Write-Error "Failed to replace ossec.conf: $_"
    exit 1
}

# Update registry uninstall DisplayName to "Cybersentinel Agent"
try {
    $key32 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC"
    $key64 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC"
    if (Test-Path $key32) { $regPath = $key32 }
    elseif (Test-Path $key64) { $regPath = $key64 }
    else { $regPath = $null }
    if ($regPath) {
        Set-ItemProperty -Path $regPath -Name "DisplayName" -Value "Cybersentinel Agent"
        Write-Host "Registry DisplayName updated to Cybersentinel Agent."
    } else {
        Write-Warning "Uninstall registry key not found; skipping DisplayName update."
    }
} catch {
    Write-Error "Failed to update registry: $_"
    exit 1
}

# Rename desktop and Start Menu shortcuts from "Wazuh Agent" to "Cybersentinel Agent"
Write-Host "Renaming shortcuts..."
$paths = @(
    [Environment]::GetFolderPath("CommonDesktopDirectory"),
    [Environment]::GetFolderPath("Desktop"),
    [Environment]::GetFolderPath("CommonPrograms"),
    [Environment]::GetFolderPath("Programs")
)
foreach ($path in $paths) {
    if (Test-Path $path) {
        Get-ChildItem -Path $path -Recurse -Filter "*.lnk" -ErrorAction SilentlyContinue `
            | Where-Object { $_.Name -like "*Wazuh Agent*" } | ForEach-Object {
                $newName = $_.Name -replace "Wazuh Agent", "Cybersentinel Agent"
                Rename-Item -Path $_.FullName -NewName $newName -Force
                Write-Host "Renamed shortcut $($_.Name) to $newName"
        }
    }
}

# Rename any Start Menu folders named "Wazuh Agent"
foreach ($path in $paths) {
    if (Test-Path $path) {
        Get-ChildItem -Path $path -Recurse -Directory -ErrorAction SilentlyContinue `
            | Where-Object { $_.Name -like "*Wazuh Agent*" } | ForEach-Object {
                $newName = $_.Name -replace "Wazuh Agent", "Cybersentinel Agent"
                Rename-Item -Path $_.FullName -NewName $newName -Force
                Write-Host "Renamed folder $($_.Name) to $newName"
        }
    }
}

# Start the Wazuh (Cybersentinel) service
Write-Host "Starting Wazuh service..."
try {
    Start-Service -Name WazuhSvc -ErrorAction Stop
    Write-Host "Wazuh service started."
} catch {
    Write-Error "Failed to start Wazuh service: $_"
    exit 1
}

# Verify service status
try {
    $svc = Get-Service -Name WazuhSvc
    if ($svc.Status -eq "Running") {
        Write-Host "Cybersentinel (Wazuh) service is running."
    } else {
        Write-Warning "Cybersentinel (Wazuh) service is installed but not running."
    }
} catch {
    Write-Warning "Could not find the Wazuh service to verify status."
}
