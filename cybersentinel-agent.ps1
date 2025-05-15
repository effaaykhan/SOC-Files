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
    } catch {}
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

# Prepare parameters for the new service
$binPath = $wmiSvc.PathName
if ($binPath.StartsWith('"') -and $binPath.EndsWith('"')) {
    $binPath = $binPath.Trim('"')
}

switch ($wmiSvc.StartMode.ToLower()) {
    "auto"     { $startupType = "Automatic" }
    "manual"   { $startupType = "Manual" }
    "disabled" { $startupType = "Disabled" }
    default    { $startupType = "Automatic" }
}

$svcAccount = $wmiSvc.StartName
$cred = $null
if ($svcAccount -match "LocalService") {
    $cred = New-Object System.Management.Automation.PSCredential("NT AUTHORITY\LocalService",(ConvertTo-SecureString '' -AsPlainText -Force))
} elseif ($svcAccount -match "NetworkService") {
    $cred = New-Object System.Management.Automation.PSCredential("NT AUTHORITY\NetworkService",(ConvertTo-SecureString '' -AsPlainText -Force))
}

# Stop the original service if running
if ($oldService.Status -eq 'Running') {
    Write-Host "Stopping original service '$oldName'..."
    Stop-Service -Name $oldName -Force
    Start-Sleep -Seconds 2
}

# Create new service
Write-Host "Creating cloned service '$newName'..."
$params = @{
    Name           = $newName
    BinaryPathName = $binPath
    DisplayName    = $newDisplay
    StartupType    = $startupType
}
if ($wmiSvc.Description) { $params["Description"] = $wmiSvc.Description }
if ($wmiSvc.Dependencies) { $params["DependsOn"] = $wmiSvc.Dependencies }
if ($cred) { $params["Credential"] = $cred }

try {
    New-Service @params
    Write-Host "Service '$newName' created successfully."
} catch {
    Write-Error "Failed to create service '$newName': $_"
    exit 1
}

# Start new service
Write-Host "Starting new service '$newName'..."
try {
    Start-Service -Name $newName
} catch {
    Write-Error "Failed to start new service: $_"
}

# Update registry uninstall entries
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

# Rename shortcuts containing 'Wazuh'
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
            if ($lnkPath -match "Wazuh") {
                $lnkPathNew = $lnkPath -replace "Wazuh","CyberSentinel"
                try {
                    Move-Item -Path $lnkPath -Destination $lnkPathNew -Force
                    Write-Host "Renamed shortcut: '$lnkPath' -> '$lnkPathNew'"
                } catch {
                    Write-Host "Failed to rename shortcut '$lnkPath'"
                }
            }
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

# Delete original service safely
$svcNew = Get-Service -Name $newName -ErrorAction SilentlyContinue
if ($svcNew -and $svcNew.Status -eq 'Running') {
    Write-Host "Attempting to delete original service '$oldName'..."
    sc.exe delete $oldName | Out-Null
    Start-Sleep -Seconds 3
    $oldSvcCheck = Get-Service -Name $oldName -ErrorAction SilentlyContinue
    if ($oldSvcCheck) {
        Write-Warning "Service '$oldName' could not be deleted immediately. It may be marked for deletion. A reboot may be required."
    } else {
        Write-Host "Original service '$oldName' deleted successfully."
    }
} else {
    Write-Error "New service '$newName' is not running. Original service not deleted."
}
