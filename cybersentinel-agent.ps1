# Set strict error handling
$ErrorActionPreference = 'Stop'

# Display ASCII art banner
Write-Host ""
Write-Host "#####  #     # #######    #####  #     #  #####  #  ####  #####  #  ####  "
Write-Host "#     # #   #   #      #     # #     # #     # # #    # #    # # #      "
Write-Host "#       # #    #      #       #     # #     # # #      #    # # #      "
Write-Host "#  ####  #     #      #       #######  #     # # #      #   #  #  #####  "
Write-Host "#     # #     #      #       #     #  #     # # #      #    # #       # "
Write-Host "#     # #     #      #     # #     #  #     # # #    # #    # # #     # "
Write-Host "#####   #####    ####  ####### #     #  #####  #  ####  #####  #  #####  "
Write-Host ""
Write-Host "#####     #####  #######  #####     #####  #     #  #####  #####  #     #  #####  "
Write-Host "#    #   #     # #       #     #   #     # #     # #     #   #   #     # #     # "
Write-Host "#    #   #       #       #         #       #     # #         #   #     # #       "
Write-Host "#####    #  #### #####    #####    #       #     # #  ####   #   #     # #  ####  "
Write-Host "#   #    #     # #             #   #       #     # #     #   #   #     # #     # "
Write-Host "#    #   #     # #       #     #   #     # #     # #     #   #   #     # #     # "
Write-Host "#####     #####  #######  #####     #####   #####   #####    #    #####   #####  "
Write-Host ""

# Define variables
$agentUrl  = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.2-1.msi"
$agentFile = "$env:TEMP\CyberSentinelAgent.msi"
$oldSvcName = "WazuhSvc"
$newSvcName = "CyberSentinelSvc"
$displayName = "CyberSentinel Agent"
$ossecDir = Join-Path ([Environment]::GetFolderPath("ProgramFilesX86")) "ossec-agent"
$confUrl  = "https://raw.githubusercontent.com/effaaykhan/SOC-Files/main/Wazuh/windows-agent.conf"
$confFile = Join-Path $ossecDir "ossec.conf"
$script1Url  = "https://raw.githubusercontent.com/effaaykhan/VirusTotal-Integration-with-Wazuh/main/remove-threat.py"
$script2Url  = "https://raw.githubusercontent.com/effaaykhan/VirusTotal-Integration-with-Wazuh/main/remove-malware.py"
$script1File = "$env:TEMP\remove-threat.py"
$script2File = "$env:TEMP\remove-malware.py"
$pythonUrl  = "https://www.python.org/ftp/python/3.13.3/python-3.13.3-amd64.exe"
$pythonFile = "$env:TEMP\python-3.13.3-amd64.exe"
$binDir  = Join-Path $ossecDir "active-response\bin"

# Download CyberSentinel Agent MSI
Write-Host "Downloading CyberSentinel Agent MSI..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $agentUrl -OutFile $agentFile

If (!(Test-Path $agentFile)) {
    Write-Error "Download failed. Exiting."
    Exit 1
}

# Install Agent Silently
Write-Host "Installing CyberSentinel Agent..." -ForegroundColor Cyan
Start-Process -FilePath msiexec.exe `
    -ArgumentList "/i `"$agentFile`" /qn /norestart" `
    -Wait -NoNewWindow

If ($LASTEXITCODE -ne 0) {
    Write-Error "Installation failed with exit code $LASTEXITCODE."
    Exit 1
}
Write-Host "CyberSentinel Agent installed successfully." -ForegroundColor Green

# Wait for WazuhSvc to appear
Write-Host "Waiting for WazuhSvc service to appear..." -ForegroundColor Cyan
$maxRetries = 30
$retryCount = 0
while (-not (Get-Service -Name $oldSvcName -ErrorAction SilentlyContinue)) {
    Start-Sleep -Seconds 5
    $retryCount++
    if ($retryCount -ge $maxRetries) {
        Write-Error "WazuhSvc service did not appear after $($maxRetries * 5) seconds. Exiting."
        Exit 1
    }
}
Write-Host "WazuhSvc detected. Proceeding with rename..." -ForegroundColor Green

# Stop WazuhSvc
Stop-Service -Name $oldSvcName -Force -ErrorAction SilentlyContinue

# Get WazuhSvc binary path from registry
$svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$oldSvcName"
$binPath = (Get-ItemProperty $svcKey -Name ImagePath).ImagePath

# Create new service CyberSentinelSvc
New-Service -Name $newSvcName `
            -BinaryPathName $binPath `
            -DisplayName $displayName `
            -StartupType Automatic

# Delete old WazuhSvc
sc.exe delete $oldSvcName
Write-Host "Service renamed: $oldSvcName ➔ $newSvcName (Display Name: $displayName)." -ForegroundColor Green

# Apply Configuration
Write-Host "Applying custom configuration..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $confUrl -OutFile $confFile -UseBasicParsing
Write-Host "Configuration file applied: $confFile" -ForegroundColor Green

# Install Python if missing
Write-Host "Checking for Python..." -ForegroundColor Cyan
if (!(Get-Command python.exe -ErrorAction SilentlyContinue)) {
    Write-Host "Python not found. Installing Python 3.13.3..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonFile

    Start-Process -FilePath $pythonFile `
        -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" `
        -Wait -NoNewWindow

    Remove-Item $pythonFile
    Write-Host "Python 3.13.3 installed successfully." -ForegroundColor Green
} else {
    Write-Host "Python is already installed. Skipping installation." -ForegroundColor Green
}

# Install PyInstaller
Write-Host "Installing/upgrading PyInstaller..." -ForegroundColor Cyan
python -m pip install --upgrade pip
python -m pip install pyinstaller
Write-Host "PyInstaller is ready." -ForegroundColor Green

# Download & Compile Active-Response Scripts
Write-Host "Downloading active-response scripts..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $script1Url -OutFile $script1File
Invoke-WebRequest -Uri $script2Url -OutFile $script2File

Write-Host "Compiling scripts with PyInstaller..." -ForegroundColor Cyan
Push-Location $env:TEMP
python -m PyInstaller -F $script1File
python -m PyInstaller -F $script2File
Pop-Location

# Move Executables
$srcExe1 = Join-Path "$env:TEMP\dist" "remove-threat.exe"
$srcExe2 = Join-Path "$env:TEMP\dist" "remove-malware.exe"

Move-Item $srcExe1 $binDir
Move-Item $srcExe2 $binDir
Write-Host "Active-response executables deployed to $binDir" -ForegroundColor Green

# Restart Service
Write-Host "Restarting CyberSentinel service..." -ForegroundColor Cyan
Restart-Service -Name $newSvcName -Force
Write-Host "Service $newSvcName restarted." -ForegroundColor Green

# Verify
If (Test-Path (Join-Path $binDir "remove-threat.exe") -and `
    Test-Path (Join-Path $binDir "remove-malware.exe")) {
    Write-Host "Active-response executables verified in bin directory." -ForegroundColor Green
} else {
    Write-Error "ERROR: Active-response executables are missing!" 
    Exit 1
}

# Clean up
Write-Host "Cleaning up temporary files..." -ForegroundColor Cyan
Remove-Item "$env:TEMP\dist","$env:TEMP\build" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $script1File,$script2File,$agentFile -Force -ErrorAction SilentlyContinue
Write-Host "Cleanup complete. Deployment finished successfully!" -ForegroundColor Green
