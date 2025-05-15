<#
.SYNOPSIS
    Installs Wazuh agent 4.11.2-1, applies custom config, and rebrands to "Cybersentinel Agent".

.DESCRIPTION
    - Downloads the Wazuh agent MSI and installs it silently with WAZUH_MANAGER set.
    - Downloads a custom ossec.conf and replaces the default config.
    - Renames Start Menu items and updates the service DisplayName to "Cybersentinel Agent".
    - Starts the Wazuh agent service and logs all actions to %TEMP%\cybersentinel-install.log.
#>

# Ensure script runs with elevated privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
        [Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "ERROR: This script must be run as Administrator."
    exit 1
}

# Stop on any non-terminating errors
$ErrorActionPreference = 'Stop'

# Initialize log file via transcript
$logFile = Join-Path $env:TEMP 'cybersentinel-install.log'
Start-Transcript -Path $logFile -Force

try {
    # Define variables
    $msiUrl     = 'https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.2-1.msi'
    $msiPath    = Join-Path $env:TEMP 'wazuh-agent-4.11.2-1.msi'
    $managerIP  = '192.168.1.69'
    $configUrl  = 'https://raw.githubusercontent.com/effaaykhan/SOC-Files/main/Wazuh/windows-agent.conf'
    $configPath = Join-Path $env:TEMP 'windows-agent.conf'

    # 1. Download the Wazuh agent MSI
    Write-Output "Downloading Wazuh agent MSI from $msiUrl..."
    Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath
    Write-Output "Downloaded MSI to $msiPath."

    # 2. Install MSI silently with WAZUH_MANAGER
    Write-Output "Installing Wazuh agent (silent)..."
    $msiArgs = "/i `"$msiPath`" /qn WAZUH_MANAGER=`"$managerIP`""
    $proc = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -NoNewWindow -PassThru
    if ($proc.ExitCode -ne 0) {
        throw "MSI installation failed with exit code $($proc.ExitCode)."
    }
    Write-Output "Wazuh agent installed successfully."

    # Determine agent installation directory based on OS architecture
    if ([Environment]::Is64BitOperatingSystem) {
        $agentDir = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
    } else {
        $agentDir = Join-Path $env:ProgramFiles 'ossec-agent'
    }
    Write-Output "Detected agent directory: $agentDir"

    # 3. Download custom ossec.conf
    Write-Output "Downloading custom ossec.conf from $configUrl..."
    Invoke-WebRequest -Uri $configUrl -OutFile $configPath
    Write-Output "Downloaded custom config to $configPath."

    # 4. Replace default config file
    $ossecConf = Join-Path $agentDir 'ossec.conf'
    if (Test-Path $ossecConf) {
        Write-Output "Stopping Wazuh agent service to replace config..."
        # Identify service name (could be 'wazuh' or 'WazuhSvc')
        $service = Get-Service -Name wazuh -ErrorAction SilentlyContinue
        if (-not $service) { $service = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue }
        if ($service -and $service.Status -eq 'Running') {
            Stop-Service -Name $service.Name -Force -ErrorAction Stop
            Write-Output "Service stopped."
        }
        # Backup existing config (optional)
        if (Test-Path $ossecConf) {
            Copy-Item $ossecConf "${ossecConf}.bak" -Force
            Write-Output "Existing ossec.conf backed up to ${ossecConf}.bak."
        }
        # Copy new config
        Copy-Item $configPath $ossecConf -Force
        Write-Output "Replaced ossec.conf with custom configuration."
    } else {
        Write-Warning "Default ossec.conf not found at $ossecConf. Skipping config replacement."
    }

    # 5. Rebrand UI components
    #    a) Update Windows Services display name
    if (-not $service) {
        $service = Get-Service -Name wazuh -ErrorAction SilentlyContinue
        if (-not $service) { $service = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue }
    }
    if ($service) {
        Write-Output "Renaming service DisplayName to 'Cybersentinel Agent'..."
        sc.exe config "$($service.Name)" DisplayName= "Cybersentinel Agent" | Out-Null
        Write-Output "Service DisplayName updated."
    } else {
        Write-Warning "Wazuh service not found; cannot update service display name."
    }

    #    b) Rename Start Menu shortcuts and program folder
    Write-Output "Rebranding Start Menu shortcuts..."
    $startMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
    # Rename the parent folder if named "Wazuh agent"
    $oldFolder = Join-Path $startMenu 'Wazuh agent'
    if (Test-Path $oldFolder) {
        Rename-Item $oldFolder 'Cybersentinel Agent' -Force
        Write-Output "Renamed '$oldFolder' to 'Cybersentinel Agent'."
    }
    # Rename any shortcut (.lnk) containing "Wazuh"
    Get-ChildItem $startMenu -Recurse -Filter '*.lnk' | Where-Object { $_.Name -match 'Wazuh' } | ForEach-Object {
        $newName = $_.Name -replace 'Wazuh Agent', 'Cybersentinel Agent'
        $newName = $newName -replace 'Wazuh', 'Cybersentinel'
        Rename-Item $_.FullName $newName -Force
        Write-Output "Renamed shortcut '$($_.Name)' to '$newName'."
    }

    #    c) Update registry Uninstall DisplayName
    Write-Output "Updating registry DisplayName entries for Uninstall..."
    $uninstallPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($path in $uninstallPaths) {
        Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $displayName = (Get-ItemProperty -Path $_.PSPath -Name DisplayName -ErrorAction Stop).DisplayName
            } catch { continue }
            if ($displayName -like '*Wazuh*' -or $displayName -like '*ossec*') {
                Set-ItemProperty -Path $_.PSPath -Name DisplayName -Value 'Cybersentinel Agent'
                Write-Output "Updated registry DisplayName in $($_.PSPath) to 'Cybersentinel Agent'."
            }
        }
    }

    # 6. Start (or restart) the Wazuh agent service and verify it runs
    if ($service) {
        Write-Output "Starting Wazuh agent service..."
        Start-Service -Name $service.Name -ErrorAction Stop
        Start-Sleep -Seconds 2
        $svcStatus = (Get-Service -Name $service.Name).Status
        if ($svcStatus -eq 'Running') {
            Write-Output "Service '$($service.Name)' is running."
        } else {
            throw "Service failed to start; status is $svcStatus."
        }
    }

    # 7. (Logging is already handled by Start-Transcript above)

    # 8. Clean up temporary files
    Write-Output "Cleaning up temporary files..."
    Remove-Item $msiPath -Force -ErrorAction SilentlyContinue
    Remove-Item $configPath -Force -ErrorAction SilentlyContinue
    Write-Output "Temporary files removed."

    Write-Output "Installation and configuration completed successfully."

} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    Stop-Transcript
    exit 1
}

# Stop logging
Stop-Transcript
