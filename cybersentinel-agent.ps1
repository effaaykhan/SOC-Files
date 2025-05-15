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
    $cred = New-Object System.Management.Automation.PSCredential
