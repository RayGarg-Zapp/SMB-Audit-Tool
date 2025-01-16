# File: Update-SMB-Protocols.ps1
Param(
    [string]$EndpointFile = "data/endpoints.txt", # File containing list of endpoints
    [bool]$DisableSMB1 = $true,                  # Disable SMBv1 if true
    [bool]$EnableSMB2 = $true,                   # Enable SMBv2 if true
    [bool]$EnableSMB3 = $true,                   # Enable SMBv3 if true
    [string]$LogFile = "data/UpdateLogs.txt"     # Log file for successes and failures
)

# Read endpoints from file
$endpoints = Get-Content -Path $EndpointFile

# Function to update SMB protocols on a single endpoint
function Update-SMBProtocols {
    Param(
        [string]$Endpoint,
        [bool]$DisableSMB1,
        [bool]$EnableSMB2,
        [bool]$EnableSMB3
    )

    try {
        Invoke-Command -ComputerName $Endpoint -ScriptBlock {
            Param($DisableSMB1, $EnableSMB2, $EnableSMB3)
            
            if ($DisableSMB1) {
                Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
            }
            if ($EnableSMB2 -or $EnableSMB3) {
                Set-SmbServerConfiguration -EnableSMB2Protocol $EnableSMB2 -EnableSMB3Protocol $EnableSMB3 -Force
            }
        } -ArgumentList $DisableSMB1, $EnableSMB2, $EnableSMB3

        # Log success
        Add-Content -Path $LogFile -Value "[$(Get-Date)] Successfully updated $Endpoint."
        Write-Host "Successfully updated $Endpoint."
    } catch {
        # Log failure
        Add-Content -Path $LogFile -Value "[$(Get-Date)] Failed to update $Endpoint: $_"
        Write-Warning "Failed to update $Endpoint: $_"
    }
}

# Create log file directory if not exists
$logDir = Split-Path -Path $LogFile
if (!(Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir }

# Process each endpoint
foreach ($endpoint in $endpoints) {
    Write-Host "Updating SMB protocols for $endpoint..."
    Update-SMBProtocols -Endpoint $endpoint -DisableSMB1 $DisableSMB1 -EnableSMB2 $EnableSMB2 -EnableSMB3 $EnableSMB3
}

Write-Host "Update process completed. Logs saved to $LogFile."
