# CyberSentinel Agent Installation Script

# ASCII Banner
$banner = @"
  ____      _           _____                      _ _ _             _       _       
 / ___| ___| |_ _ __   | ____|_  _____  ___ _   _| | (_) __ _ _ __ (_)_ __ | |_ ___ 
| |  _ / _ \ __| '__|  |  _| \ \/ / _ \/ __| | | | | | |/ _` | '_ \| | '_ \| __/ _ \
| |_| |  __/ |_| |     | |___ >  <  __/ (__| |_| | | | | (_| | | | | | | | | ||  __/
 \____|\___|\__|_|     |_____/ _/\_\___|\___|\__,_|_|_|_|\__,_|_| |_|_|_| |_|\__\___|
                                                                            _/ |        
                                                                           |__/         
 CyberSentinel Agent Installation
"@
Write-Host $banner

$ErrorActionPreference = 'Stop'

# Create a temporary directory for downloads and builds
$tempDir = Join-Path $env:TEMP 'CyberSentinelAgent'
if (!(Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir | Out-Null }

# 1. Download and Install Wazuh Agent (rebranded)
$agentUrl = 'https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.2-1.msi'
$installerPath = Join-Path $tempDir 'wazuh-agent-4.11.2-1.msi'

Write-Host "Downloading CyberSentinel Agent installer..."
try {
    Invoke-WebRequest -Uri $agentUrl -OutFile $installerPath -UseBasicParsing
    Write-Host "Downloaded installer to $installerPath"
} catch {
    Write-Error "Failed to download agent installer: $($_.Exception.Message)"; exit 1
}

Write-Host "Installing CyberSentinel Agent..."
try {
    Start-Process msiexec.exe -ArgumentList "/i `"$installerPath`" /qn" -Wait -NoNewWindow
    Write-Host "CyberSentinel Agent installation completed."
} catch {
    Write-Error "Agent installation failed: $($_.Exception.Message)"; exit 1
}

# 2. Apply Custom ossec.conf Configuration
Write-Host "Stopping CyberSentinel Agent service..."
Stop-Service -Name WazuhSvc -Force -ErrorAction SilentlyContinue
Stop-Service -Name Wazuh    -Force -ErrorAction SilentlyContinue

$configUrl = 'https://raw.githubusercontent.com/effaaykhan/SOC-Files/main/Wazuh/windows-agent.conf'
$configPath = 'C:\Program Files (x86)\ossec-agent\ossec.conf'

Write-Host "Applying custom configuration (ossec.conf)..."
try {
    Invoke-WebRequest -Uri $configUrl -OutFile $configPath -UseBasicParsing
    Write-Host "Custom configuration applied to $configPath"
} catch {
    Write-Error "Failed to apply custom configuration: $($_.Exception.Message)"; exit 1
}

# 3. Check for Python and Install if Missing
Write-Host "Checking for Python installation..."
try {
    $pythonVersion = (& python --version) -replace 'Python ', '' 2>$null
} catch {
    $pythonVersion = $null
}

if ($pythonVersion) {
    Write-Host "Python is already installed (Version $pythonVersion)."
} else {
    $userInput = Read-Host "Python is not installed. Install latest Python now? (Y/N)"
    if ($userInput -match '^[Yy]') {
        Write-Host "Downloading Python installer..."
        $pythonUrl = 'https://www.python.org/ftp/python/3.13.3/python-3.13.3-amd64.exe'
        $pythonInstaller = Join-Path $tempDir 'python-latest-amd64.exe'
        try {
            Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstaller -UseBasicParsing
            Write-Host "Installing Python silently..."
            Start-Process -FilePath $pythonInstaller -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_pip=1" -Wait -NoNewWindow
            Write-Host "Python installation completed."
        } catch {
            Write-Error "Failed to install Python: $($_.Exception.Message)"; exit 1
        }
    } else {
        Write-Error "Python installation canceled by user. Cannot continue."; exit 1
    }
}

# 4. Install PyInstaller via pip
Write-Host "Installing PyInstaller..."
try {
    Start-Process -FilePath "python" -ArgumentList "-m pip install --upgrade pyinstaller" -Wait -NoNewWindow
    Write-Host "PyInstaller installed successfully."
} catch {
    Write-Error "PyInstaller installation failed: $($_.Exception.Message)"; exit 1
}

# 5. Download Active-Response Python Scripts
Write-Host "Downloading active-response scripts..."
$threatPy = Join-Path $tempDir 'remove-threat.py'
$malwarePy = Join-Path $tempDir 'remove-malware.py'
try {
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/effaaykhan/VirusTotal-Integration-with-Wazuh/main/remove-threat.py' -OutFile $threatPy -UseBasicParsing
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/effaaykhan/VirusTotal-Integration-with-Wazuh/main/remove-malware.py' -OutFile $malwarePy -UseBasicParsing
    Write-Host "Downloaded Python scripts for active-response."
} catch {
    Write-Error "Failed to download active-response scripts: $($_.Exception.Message)"; exit 1
}

# 6. Build Executables with PyInstaller
Write-Host "Building executables from Python scripts..."
try {
    Start-Process -FilePath "pyinstaller" -ArgumentList "-F `"$threatPy`"" -Wait -NoNewWindow
    Start-Process -FilePath "pyinstaller" -ArgumentList "-F `"$malwarePy`"" -Wait -NoNewWindow
    Write-Host "Executables built successfully."
} catch {
    Write-Error "Failed to build executables: $($_.Exception.Message)"; exit 1
}

# 7. Deploy Executables to Active-Response Bin
$binDir = 'C:\Program Files (x86)\ossec-agent\active-response\bin'
Write-Host "Deploying executables to active-response bin..."
try {
    Copy-Item -Path (Join-Path $tempDir 'dist\remove-threat.exe')   -Destination (Join-Path $binDir 'remove-threat.exe')   -Force
    Copy-Item -Path (Join-Path $tempDir 'dist\remove-malware.exe') -Destination (Join-Path $binDir 'remove-malware.exe') -Force
    if (Test-Path (Join-Path $binDir 'remove-threat.exe') -and Test-Path (Join-Path $binDir 'remove-malware.exe')) {
        Write-Host "Executables successfully deployed to $binDir."
    } else {
        Write-Error "Executable files not found in $binDir."; exit 1
    }
} catch {
    Write-Error "Failed to copy executables: $($_.Exception.Message)"; exit 1
}

# 8. Restart Agent Service
Write-Host "Restarting CyberSentinel Agent service..."
try {
    Stop-Service -Name WazuhSvc -Force -ErrorAction SilentlyContinue
    Stop-Service -Name Wazuh    -Force -ErrorAction SilentlyContinue
    Start-Service -Name WazuhSvc -ErrorAction SilentlyContinue
    Start-Service -Name Wazuh    -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
    Write-Host "CyberSentinel Agent service restarted successfully."
} catch {
    Write-Error "Failed to restart agent service: $($_.Exception.Message)"; exit 1
}

# 9. Cleanup
Write-Host "Cleaning up temporary files..."
try {
    Remove-Item -Path $tempDir -Recurse -Force
    Write-Host "Temporary files removed."
} catch {
    Write-Warning "Could not completely remove temporary files: $($_.Exception.Message)"
}
Write-Host "CyberSentinel Agent installation completed successfully."
