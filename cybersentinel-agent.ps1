# Ensure the script is running as Administrator
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# Define original and new service names
$oldNames = @("WazuhSvc","Wazuh")      # Possible Wazuh service names
$newName   = "CyberSentinelAgent"      # New service name
$newDisplay= "CyberSentinel Agent"     # New display name in Services

# Find the existing Wazuh service (if installed)
$oldService = $null
foreach ($nm in $oldNames) {
    try {
        $svcTemp = Get-Service -Name $nm -ErrorAction Stop
        $oldService = $svcTemp
        break
    } catch {
        # Try next name if not found
    }
}
if (-not $oldService) {
    Write-Error "Original Wazuh service not found. Ensure Wazuh Agent is installed."
    exit 1
}
$oldName = $oldService.Name
Write-Host "Found Wazuh service: Name='$oldName', DisplayName='$($oldService.DisplayName)'."

# Retrieve current configuration for the Wazuh service
$wmiSvc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$oldName'"
if (-not $wmiSvc) {
    Write-Error "Failed to retrieve service configuration for $oldName."
    exit 1
}

# Prepare parameters for the new service (clone with same settings)
$binPath = $wmiSvc.PathName
# Remove enclosing quotes if present (New-Service will handle quoting)
if ($binPath.StartsWith('"') -and $binPath.EndsWith('"')) {
    $binPath = $binPath.Trim('"')
}

# Determine startup type (Auto, Manual, Disabled)
switch ($wmiSvc.StartMode.ToLower()) {
    "auto"     { $startupType = "Automatic" }
    "manual"   { $startupType = "Manual" }
    "disabled" { $startupType = "Disabled" }
    default    { $startupType = "Automatic" }
}

# Determine service account credentials if needed (LocalSystem, LocalService, NetworkService)
$svcAccount = $wmiSvc.StartName
$cred = $null
if ($svcAccount -match "LocalService") {
    $cred = New-Object System.Management.Automation.PSCredential("NT AUTHORITY\LocalService",(ConvertTo-SecureString '' -AsPlainText -Force))
} elseif ($svcAccount -match "NetworkService") {
    $cred = New-Object System.Management.Automation.PSCredential("NT AUTHORITY\NetworkService",(ConvertTo-SecureString '' -AsPlainText -Force))
} elseif ($svcAccount -like "*LocalSystem") {
    # LocalSystem account does not require explicit credentials
    $cred = $null
} else {
    Write-Host "Service runs under '$svcAccount'. Manual credential entry may be required."
    $cred = $null
}

# Stop the original Wazuh service if it's running
if ($oldService.Status -eq 'Running') {
    Write-Host "Stopping original service '$oldName'..."
    Stop-Service -Name $oldName -Force
}

# Create the cloned service with the new name and same configuration
Write-Host "Creating cloned service '$newName'..."
$params = @{
    Name           = $newName
    BinaryPathName = $binPath
    DisplayName    = $newDisplay
    StartupType    = $startupType
}
# Copy description if it exists
if ($wmiSvc.Description) {
    $params["Description"] = $wmiSvc.Description
}
# Copy any dependencies
if ($wmiSvc.Dependencies) {
    $params["DependsOn"] = $wmiSvc.Dependencies
}
# Include credentials if using LocalService or NetworkService
if ($cred) {
    $params["Credential"] = $cred
}
try {
    New-Service @params
    Write-Host "Service '$newName' created successfully."
} catch {
    Write-Error "Failed to create service '$newName': $_"
    exit 1
}

# Start the new CyberSentinel service
Write-Host "Starting new service '$newName'..."
Start-Service -Name $newName

# Update registry uninstall entries: replace 'Wazuh' with 'CyberSentinel' in DisplayName
$uninstallPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)
foreach ($path in $uninstallPaths) {
    if (Test-Path $path) {
        Get-ChildItem $path | ForEach-Object {
            try {
                $disp = (Get-ItemProperty $_.PSPath -Name "DisplayName" -ErrorAction Stop).DisplayName
            } catch { return }
            if ($disp -match "Wazuh") {
                $newDisp = $disp -replace "Wazuh","CyberSentinel"
                Write-Host "Updating registry DisplayName: '$disp' -> '$newDisp' in $($_.PSPath)"
                Set-ItemProperty -Path $_.PSPath -Name "DisplayName" -Value $newDisp
            }
        }
    }
}

# Update shortcuts (Start Menu / Desktop) containing 'Wazuh' to 'CyberSentinel'
$wshell = New-Object -ComObject WScript.Shell
$folders = @(
    [Environment]::GetFolderPath("CommonPrograms"),
    [Environment]::GetFolderPath("Programs"),
    [Environment]::GetFolderPath("CommonDesktopDirectory"),
    [Environment]::GetFolderPath("Desktop")
)
foreach ($folder in $folders) {
    if (-not [string]::IsNullOrEmpty($folder) -and (Test-Path $folder)) {
        Get-ChildItem -Path $folder -Recurse -Include *.lnk -ErrorAction SilentlyContinue | ForEach-Object {
            $lnkPath    = $_.FullName
            $lnkPathNew = $lnkPath
            # Rename shortcut file if it contains 'Wazuh'
            if ($lnkPath -match "Wazuh") {
                $lnkPathNew = $lnkPath -replace "Wazuh","CyberSentinel"
                try {
                    Move-Item -Path $lnkPath -Destination $lnkPathNew -Force
                    Write-Host "Renamed shortcut: '$lnkPath' -> '$lnkPathNew'"
                } catch {
                    Write-Host "Failed to rename shortcut '$lnkPath'"
                }
            }
            # Update the shortcut's description if needed
            if (Test-Path $lnkPathNew) {
                $shortcut = $wshell.CreateShortcut($lnkPathNew)
                if ($shortcut.Description -and $shortcut.Description -match "Wazuh") {
                    $shortcut.Description = $shortcut.Description -replace "Wazuh","CyberSentinel"
                    $shortcut.Save()
                    Write-Host "Updated shortcut description in '$lnkPathNew'."
                }
            }
        }
    }
}

# Delete the original Wazuh service now that the new one is running
$svcNew = Get-Service -Name $newName
if ($svcNew.Status -eq 'Running') {
    Write-Host "Deleting original service '$oldName'..."
    sc.exe delete $oldName | Out-Null
    Write-Host "Original service '$oldName' deleted."
} else {
    Write-Error "New service '$newName' is not running. Original service not deleted."
}
