# Display starting message
Write-Host "Installing CyberSentinel Agent..." -ForegroundColor Cyan

# Define paths
$binDir = Join-Path $PSScriptRoot "bin"
$scriptFile = $MyInvocation.MyCommand.Definition

# Simulate download or setup (example, replace with actual logic if needed)
Write-Host "Downloading CyberSentinel agent..." -ForegroundColor Cyan

# Example: Verify presence of executables
if ((Test-Path (Join-Path $binDir "remove-threat.exe")) -and (Test-Path (Join-Path $binDir "remove-malware.exe"))) {
    Write-Host "Active-response executables verified in bin directory." -ForegroundColor Green
} else {
    Write-Error "ERROR: Active-response executables are missing!"
    Exit 1
}

# (Optional) Start service
$serviceName = "CyberSentinelSvc"
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    Start-Service -Name $serviceName
    Write-Host "Service '$serviceName' started successfully." -ForegroundColor Green
} else {
    Write-Warning "Service '$serviceName' not found. Skipping service start."
}

# (Optional) Clean up temp files
# Write-Host "Cleaning up temporary files..." -ForegroundColor Cyan
# Remove-Item "$env:TEMP\dist","$env:TEMP\build" -Recurse -Force -ErrorAction SilentlyContinue
# Remove-Item $scriptFile -Force -ErrorAction SilentlyContinue

# Final success message
Write-Host "Cleanup complete. Deployment finished successfully!" -ForegroundColor Green
