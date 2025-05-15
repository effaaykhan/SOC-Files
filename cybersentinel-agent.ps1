# Fixed CyberSentinel agent installation script
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

try {
    # Ensure script is run as Administrator
    $user = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($user)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator privileges are required to run this script."
    }

    Write-Host "Installing CyberSentinel Agent..."

    # Variables (replace <URL> placeholders with actual URLs)
    $tempDir = Join-Path $env:TEMP "CyberSentinelAgent"
    $agentMsiUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.2-1.msi"
    $agentMsiPath = Join-Path $tempDir "cybersentinel-agent.msi"
    $pythonInstallerUrl = "https://www.python.org/downloads/release/python-3133/"
    $pythonInstallerPath = Join-Path $tempDir "python-installer.exe"
    $ossecConfigUrl = "https://github.com/effaaykhan/SOC-Files/blob/main/Wazuh/windows-agent.conf"
    # Determine agent installation path (Wazuh default)
    if ([Environment]::Is64BitProcess) {
        $agentPath = "${env:ProgramFiles(x86)}\ossec-agent"
    } else {
        $agentPath = "${env:ProgramFiles}\ossec-agent"
    }

    # Create temporary folder
    if (Test-Path $tempDir) { Remove-Item -Path $tempDir -Recurse -Force }
    New-Item -Path $tempDir -ItemType Directory | Out-Null

    # Download and install the CyberSentinel (Wazuh) agent silently
    Write-Host "Downloading CyberSentinel agent..."
    Invoke-WebRequest -Uri $agentMsiUrl -OutFile $agentMsiPath -UseBasicParsing
    Start-Process msiexec.exe -ArgumentList "/i `"$agentMsiPath`" /quiet /norestart" -Wait

    # Rename the service to CyberSentinelSvc
    if (Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue) {
        Stop-Service -Name "WazuhSvc" -Force -ErrorAction SilentlyContinue
        $oldKey = "HKLM:\SYSTEM\CurrentControlSet\Services\WazuhSvc"
        $binPath = (Get-ItemProperty -Path $oldKey -Name ImagePath).ImagePath
        $startType = (Get-ItemProperty -Path $oldKey -Name Start).Start
        # Create new service with the same executable
        sc.exe create CyberSentinelSvc binPath= "\"$binPath\"" start= $startType DisplayName= "CyberSentinel Agent" | Out-Null
        sc.exe description CyberSentinelSvc "CyberSentinel Agent Service" | Out-Null
        sc.exe delete WazuhSvc | Out-Null
    }
    Set-Service -Name CyberSentinelSvc -StartupType Automatic

    # Download and apply custom ossec.conf (if provided)
    Write-Host "Applying custom ossec.conf..."
    if ($ossecConfigUrl) {
        $configPath = Join-Path $agentPath "ossec.conf"
        Invoke-WebRequest -Uri $ossecConfigUrl -OutFile $configPath -UseBasicParsing
    }

    # Install Python if not already installed
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        Write-Host "Installing Python..."
        Invoke-WebRequest -Uri $pythonInstallerUrl -OutFile $pythonInstallerPath -UseBasicParsing
        Start-Process -FilePath $pythonInstallerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
    }

    # Build active-response executables using PyInstaller
    Write-Host "Building executables from Python scripts..."
    $activeRespZip = Join-Path $tempDir "active-response.zip"
    $activeRespDir = Join-Path $tempDir "active-response"
    # Download the active-response scripts (replace with actual URL)
    Invoke-WebRequest -Uri "https://github.com/effaaykhan/VirusTotal-Integration-with-Wazuh/blob/main/remove-malware.py" -OutFile $activeRespZip -UseBasicParsing
    Expand-Archive -LiteralPath $activeRespZip -DestinationPath $activeRespDir -Force

    # Install PyInstaller via pip
    python -m pip install --upgrade pip | Out-Null
    python -m pip install pyinstaller | Out-Null

    # Compile each .py script to .exe
    Push-Location $activeRespDir
    $distDir = Join-Path $activeRespDir "dist"
    if (Test-Path $distDir) { Remove-Item -Recurse -Force $distDir }
    Get-ChildItem -Path $activeRespDir -Filter "*.py" | ForEach-Object {
        python -m PyInstaller --noconfirm --onefile $_.FullName | Out-Null
    }
    Pop-Location

    # Copy compiled executables to the agent's Active-Response\bin folder
    Write-Host "Deploying active-response executables..."
    $binDir = Join-Path $agentPath "Active-Response\bin"
    if (-not (Test-Path $binDir)) { New-Item -ItemType Directory -Path $binDir | Out-Null }
    Get-ChildItem -Path (Join-Path $activeRespDir "dist") -Filter "*.exe" | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination $binDir -Force
    }

    # Restart the CyberSentinel service
    Write-Host "Restarting CyberSentinel service..."
    Restart-Service -Name CyberSentinelSvc -Force

    # Cleanup temp files
    Remove-Item -Path $tempDir -Recurse -Force
    Write-Host "CyberSentinel agent installation and configuration complete."
    exit 0
}
catch {
    Write-Error "Installation failed: $_"
    exit 1
}
