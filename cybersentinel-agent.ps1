<# 
    Cybersentinel Agent Installation and Rebranding Script
    - Downloads and installs the Wazuh agent
    - Updates agent configuration
    - Changes the service display name to "Cybersentinel Agent"
    - Renames Start Menu shortcuts and registry entries
#>

# Define the address of the Wazuh (Ossec) manager; update as needed
$WazuhManager = '192.168.1.100'  # <--- CHANGE THIS to your Wazuh Manager IP or hostname
$AgentGroup = 'default'          # optional agent group

# Ensure script is running as Administrator
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "This script must be run as Administrator. Exiting."
    Exit 1
}

# Ensure we are running in 64-bit PowerShell on 64-bit Windows
if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
    Write-Output "Not running in 64-bit PowerShell. Restarting in 64-bit mode..."
    $ps64 = "$env:windir\SysNative\WindowsPowerShell\v1.0\powershell.exe"
    if (-not (Test-Path $ps64)) {
        $ps64 = "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe"
    }
    Start-Process -FilePath $ps64 -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"" + $MyInvocation.MyCommand.Definition + "`"" -Verb RunAs
    Exit
}

# Setup a simple logging function
$LogFile = "$env:TEMP\cybersentinel_install.log"
if (Test-Path $LogFile) { Remove-Item $LogFile -ErrorAction SilentlyContinue }
Function Write-Log {
    param([string]$msg, [string]$level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "$timestamp [$level] $msg"
    Write-Output $entry
    Add-Content -Path $LogFile -Value $entry
}

Write-Log "===== Starting Cybersentinel Agent Installation and Rebranding ====="
Write-Log "Wazuh Manager: $WazuhManager; Agent Group: $AgentGroup"

Try {
    # Step 1: Download the latest Wazuh Agent installer (64-bit)
    $WazuhVersion = "4.5.0" # specify or update to current version (e.g., 4.12.0)
    $WazuhMsiName = "wazuh-agent-$WazuhVersion-1.msi"
    $DownloadUrl = "https://packages.wazuh.com/4.x/windows/$WazuhMsiName"
    $InstallerPath = Join-Path $env:TEMP $WazuhMsiName

    Write-Log "Downloading Wazuh Agent MSI from $DownloadUrl"
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $InstallerPath -UseBasicParsing -ErrorAction Stop
    Write-Log "Downloaded installer to $InstallerPath"

    # Step 2: Install the Wazuh Agent silently
    Write-Log "Installing Wazuh Agent..."
    $msiArgs = @("/i", "`"$InstallerPath`"", "/qn")
    $agentName = $env:COMPUTERNAME
    $msiArgs += "WAZUH_MANAGER=`"$WazuhManager`""
    $msiArgs += "WAZUH_AGENT_GROUP=`"$AgentGroup`""
    $msiArgs += "WAZUH_AGENT_NAME=`"$agentName`""
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -NoNewWindow -Wait -Passthru
    if ($process.ExitCode -ne 0) {
        Write-Log "Wazuh MSI installation failed with exit code $($process.ExitCode)" "ERROR"
        throw "Installation error"
    }
    Write-Log "Wazuh Agent installation completed successfully."

    # Step 3: Update the agent configuration (ossec.conf) with manager address and agent name
    $ossecPath = "$env:ProgramFiles\ossec-agent"
    if (-not (Test-Path $ossecPath)) {
        $ossecPath = "$env:ProgramFiles(x86)\ossec-agent"
    }
    $configFile = Join-Path $ossecPath "ossec.conf"
    if (Test-Path $configFile) {
        Write-Log "Updating ossec.conf at $configFile"
        try {
            [xml]$ossecConfig = Get-Content $configFile
            if ($ossecConfig.ossec_config.client.server.address) {
                $ossecConfig.ossec_config.client.server.address = $WazuhManager
            }
            if ($ossecConfig.ossec_config.client.name) {
                $ossecConfig.ossec_config.client.name = $agentName
            } else {
                $clientNode = $ossecConfig.ossec_config.client
                $nameNode = $ossecConfig.CreateElement("name")
                $nameNode.InnerText = $agentName
                $clientNode.AppendChild($nameNode) | Out-Null
            }
            $ossecConfig.Save($configFile)
            Write-Log "ossec.conf updated with manager $WazuhManager and agent name $agentName"
        } catch {
            Write-Log "Failed to update ossec.conf: $_" "ERROR"
        }
    } else {
        Write-Log "Configuration file not found at $configFile" "WARN"
    }

    # Step 4: Change the Windows service display name to "Cybersentinel Agent"
    $serviceName = "WazuhSvc"  # default service name for Wazuh agent
    $displayName = "Cybersentinel Agent"
    Write-Log "Setting service display name to '$displayName'"
    try {
        Set-Service -Name $serviceName -DisplayName $displayName -ErrorAction Stop
        Write-Log "Service display name set to '$displayName'"
    } catch {
        Write-Log "Failed to set service display name: $_" "ERROR"
    }

    # Step 5: Rename Start Menu shortcuts and folders from 'Wazuh' to 'Cybersentinel'
    $searchPatterns = @("Wazuh", "WAZUH")
    $startMenuPaths = @(
        [Environment]::GetFolderPath("CommonPrograms"),
        [Environment]::GetFolderPath("Programs")
    )
    foreach ($menuPath in $startMenuPaths) {
        if (Test-Path $menuPath) {
            Get-ChildItem -Path $menuPath -Recurse -Force | ForEach-Object {
                $item = $_
                foreach ($pattern in $searchPatterns) {
                    if ($item.Name -like "*$pattern*") {
                        $newName = $item.Name -replace $pattern, "Cybersentinel"
                        try {
                            Rename-Item -Path $item.FullName -NewName $newName -ErrorAction Stop
                            Write-Log "Renamed '$($item.FullName)' to '$newName'"
                        } catch {
                            Write-Log "Failed to rename '$($item.FullName)': $_" "ERROR"
                        }
                        break
                    }
                }
            }
        }
    }

    # Also rename any Wazuh shortcuts on the desktop
    $desktopPaths = @(
        [Environment]::GetFolderPath("CommonDesktopDirectory"),
        [Environment]::GetFolderPath("Desktop")
    )
    foreach ($desk in $desktopPaths) {
        if (Test-Path $desk) {
            Get-ChildItem -Path $desk -Filter "*.lnk" -Force | ForEach-Object {
                $shortcut = $_
                foreach ($pattern in $searchPatterns) {
                    if ($shortcut.Name -like "*$pattern*") {
                        $newName = $shortcut.Name -replace $pattern, "Cybersentinel"
                        try {
                            Rename-Item -Path $shortcut.FullName -NewName $newName -ErrorAction Stop
                            Write-Log "Renamed desktop shortcut '$($shortcut.FullName)' to '$newName'"
                        } catch {
                            Write-Log "Failed to rename desktop shortcut '$($shortcut.FullName)': $_" "ERROR"
                        }
                        break
                    }
                }
            }
        }
    }

    # Step 6: Update registry uninstall DisplayName entries for Wazuh agent
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($path in $uninstallPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path | ForEach-Object {
                try {
                    $props = Get-ItemProperty -Path $_.PSPath -Name "DisplayName" -ErrorAction Stop
                    if ($props.DisplayName -and $props.DisplayName -match "Wazuh") {
                        Write-Log "Updating registry uninstall entry in '$($_.PSChildName)'"
                        Set-ItemProperty -Path $_.PSPath -Name "DisplayName" -Value "Cybersentinel Agent" -ErrorAction Stop
                    }
                } catch {
                    # skip if no DisplayName or access issues
                }
            }
        }
    }

    # Step 7: Start the service under the original service name
    Write-Log "Starting service '$serviceName'"
    try {
        Start-Service -Name $serviceName -ErrorAction Stop
        Write-Log "Service '$serviceName' started successfully."
    } catch {
        Write-Log "Failed to start service '$serviceName': $_" "ERROR"
    }

    Write-Log "===== Cybersentinel Agent installation and rebranding completed successfully ====="
} Catch {
    Write-Log "An unexpected error occurred: $_" "ERROR"
    Write-Log "Installation aborted."
    Exit 1
}
