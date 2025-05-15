# Display starting message
Write-Host "Installing CyberSentinel Agent..." -ForegroundColor Cyan

# Define paths
$binDir = Join-Path $PSScriptRoot "bin"
$oldAgentExe = Join-Path $binDir "agent.exe"            # assuming original name
$newAgentExe = Join-Path $binDir "cybersentinel.exe"    # new name to use

# Rename agent executable if it exists and not already renamed
if (Test-Path $oldAgentExe) {
    Rename-Item -Path $oldAgentExe -NewName "cybersentinel.exe" -Force
    Write-Host "Agent executable renamed to 'cybersentinel.exe'." -ForegroundColor Green
} elseif (Test-Path $newAgentExe) {
    Write-Host "Agent executable already named 'cybersentinel.exe'." -ForegroundColor Green
} else {
    Write-Warning "Agent executable not found in bin directory."
}

# Service name to use
$serviceName = "CyberSentinel"

# Start the service if it exists
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    Start-Service -Name $serviceName
    Write-Host "Service '$serviceName' started successfully." -ForegroundColor Green
} else {
    Write-Warning "Service '$serviceName' not found. Skipping service start."
}

# Final success message
Write-Host "Deployment finished successfully!" -ForegroundColor Green
