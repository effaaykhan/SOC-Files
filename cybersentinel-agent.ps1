Write-Host "Installing CyberSentinel Agent..." -ForegroundColor Cyan

# Variables
$agentUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.2-1.msi"   # REPLACE this with your actual agent archive URL
$tempZip = Join-Path $env:TEMP "cybersentinel-agent.zip"
$installDir = Join-Path $PSScriptRoot "bin"
$oldAgentExe = "agent.exe"              # original agent exe name inside the zip
$newAgentExe = "cybersentinel.exe"
$serviceName = "CyberSentinel"

# Download agent zip
Write-Host "Downloading CyberSentinel agent..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $agentUrl -OutFile $tempZip

# Create install directory if missing
if (-not (Test-Path $installDir)) {
    New-Item -Path $installDir -ItemType Directory | Out-Null
}

# Extract agent archive
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory($tempZip, $installDir)

# Delete zip file
Remove-Item $tempZip -Force

# Rename agent executable if exists
$oldExePath = Join-Path $installDir $oldAgentExe
$newExePath = Join-Path $installDir $newAgentExe
if (Test-Path $oldExePath) {
    Rename-Item -Path $oldExePath -NewName $newAgentExe -Force
    Write-Host "Renamed agent executable to '$newAgentExe'." -ForegroundColor Green
} elseif (Test-Path $newExePath) {
    Write-Host "Agent executable already named '$newAgentExe'." -ForegroundColor Green
} else {
    Write-Warning "Agent executable not found in bin directory!"
}

# Remove existing service if any
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    Write-Host "Stopping existing service '$serviceName'..."
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    Write-Host "Removing existing service '$serviceName'..."
    sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 2
}

# Create new service
$exePathQuoted = "`"$newExePath`""
Write-Host "Installing service '$serviceName'..."
sc.exe create $serviceName binPath= $exePathQuoted start= auto | Out-Null

# Start the service
Start-Service -Name $serviceName
Write-Host "Service '$serviceName' started successfully." -ForegroundColor Green

Write-Host "Deployment finished successfully!" -ForegroundColor Green
