# CyberSentinel Agent Installation Script
function Write-CS($msg) { Write-Host "[CyberSentinel] $msg" }

# Banner
$banner = @"
===========================================
=         CYBERSENTINEL AGENT            =
===========================================
"@
Write-Host $banner
Write-CS "Initializing CyberSentinel agent installation..."

# Step 1: Download and Install Wazuh Agent
$agentUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.2-1.msi"
$msiPath = Join-Path $env:TEMP "wazuh-agent-4.11.2-1.msi"
Write-CS "Downloading Wazuh agent MSI..."
Invoke-WebRequest -Uri $agentUrl -OutFile $msiPath

Write-CS "Installing Wazuh (CyberSentinel) Agent silently..."
Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$msiPath`" /qn /norestart" -Wait
if ($LASTEXITCODE -ne 0) { throw "MSI installation failed with code $LASTEXITCODE" }

# Step 2: Rename Wazuh Service to CyberSentinelSvc
Write-CS "Stopping existing Wazuh service..."
Stop-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue

if (Test-Path "${env:ProgramFiles(x86)}\ossec-agent") {
    $ossecPath = "${env:ProgramFiles(x86)}\ossec-agent"
} elseif (Test-Path "${env:ProgramFiles}\ossec-agent") {
    $ossecPath = "${env:ProgramFiles}\ossec-agent"
} else {
    throw "Wazuh Agent installation directory not found."
}

$binPath = "`"$ossecPath\ossec-agent.exe`""
Write-CS "Renaming Wazuh service to CyberSentinelSvc..."
Start-Process -FilePath "sc.exe" -ArgumentList "create CyberSentinelSvc binPath= $binPath DisplayName= `"CyberSentinel Agent`" start= auto obj= LocalSystem" -Wait
Start-Process -FilePath "sc.exe" -ArgumentList "delete WazuhSvc" -Wait

Write-CS "Starting CyberSentinelSvc..."
Start-Service -Name "CyberSentinelSvc"
Start-Sleep -Seconds 5
if ((Get-Service -Name "CyberSentinelSvc").Status -ne 'Running') {
    throw "CyberSentinelSvc failed to start."
}

# Step 3: Apply Custom ossec.conf
$configUrl = "https://raw.githubusercontent.com/effaaykhan/SOC-Files/main/Wazuh/windows-agent.conf"
$configPath = Join-Path $ossecPath "ossec.conf"
Write-CS "Downloading custom ossec.conf..."
Invoke-WebRequest -Uri $configUrl -OutFile $configPath

Write-CS "Restarting service to apply config..."
Stop-Service -Name "CyberSentinelSvc"
Start-Service -Name "CyberSentinelSvc"
Write-CS "Configuration applied successfully."

# Step 4: Install Python & PyInstaller
function Install-Python {
    Write-CS "Installing Python..."
    $arch = if ($ENV:PROCESSOR_ARCHITECTURE -match "AMD64") { "amd64" } else { "" }
    $pyVersion = "3.13.3"
    $pythonExe = if ($arch -eq "amd64") {
        "python-$pyVersion-$arch.exe"
    } else {
        "python-$pyVersion.exe"
    }
    $pythonUrl = "https://www.python.org/ftp/python/$pyVersion/$pythonExe"
    $pyPath = Join-Path $env:TEMP $pythonExe
    Invoke-WebRequest -Uri $pythonUrl -OutFile $pyPath
    Start-Process -FilePath $pyPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
    Remove-Item $pyPath -Force
    Write-CS "Python installed."
}

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Install-Python
} else {
    Write-CS "Python already installed."
}

# Reload path in current session
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
Write-CS "Installing PyInstaller..."
Start-Process -FilePath "python" -ArgumentList "-m pip install pyinstaller" -Wait

# Step 5: Compile and Move Active Response Scripts
$activeRespScripts = @("remove-threat.py","remove-malware.py")
foreach ($scriptName in $activeRespScripts) {
    $url = "https://raw.githubusercontent.com/effaaykhan/VirusTotal-Integration-with-Wazuh/main/$scriptName"
    $localPy = Join-Path $env:TEMP $scriptName
    Write-CS "Downloading $scriptName..."
    Invoke-WebRequest -Uri $url -OutFile $localPy

    Write-CS "Compiling $scriptName..."
    Start-Process -FilePath "pyinstaller" -ArgumentList "-F `"$localPy`"" -NoNewWindow -Wait

    # Move .exe to active-response\bin
    $exeName = [System.IO.Path]::GetFileNameWithoutExtension($scriptName) + ".exe"
    $exeSource = Join-Path (Join-Path (Get-Location) "dist") $exeName
    $exeTargetDir = Join-Path $ossecPath "active-response\bin"
    if (-not (Test-Path $exeTargetDir)) {
        throw "Target directory $exeTargetDir does not exist."
    }
    Move-Item -Path $exeSource -Destination (Join-Path $exeTargetDir $exeName) -Force
    Write-CS "Moved $exeName to $exeTargetDir"
}

# Step 6: Final Checks and Cleanup
$threatExe = Join-Path $ossecPath "active-response\bin\remove-threat.exe"
$malwareExe = Join-Path $ossecPath "active-response\bin\remove-malware.exe"
if ((Test-Path $threatExe) -and (Test-Path $malwareExe)) {
    Write-CS "All active-response scripts compiled and deployed successfully."
} else {
    throw "One or more .exe files missing from $($ossecPath)\active-response\bin"
}

Write-CS "Restarting CyberSentinelSvc for final confirmation..."
Restart-Service -Name "CyberSentinelSvc"

# Cleanup
Write-CS "Cleaning temporary files..."
Remove-Item $msiPath -Force -ErrorAction SilentlyContinue
Get-ChildItem $env:TEMP -Filter "remove-*.py" | Remove-Item -Force -ErrorAction SilentlyContinue
Remove-Item ".\build" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item ".\dist" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item ".\__pycache__" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item ".\*.spec" -Force -ErrorAction SilentlyContinue

Write-CS "✅ CyberSentinel Agent setup completed successfully!"
