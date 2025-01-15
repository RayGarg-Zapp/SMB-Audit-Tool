# File: Update-SMB-Protocols.ps1
Param(
    [string]$EndpointFile = "endpoints.txt", # File containing list of endpoints
    [bool]$DisableSMB1 = $true,             # Disable SMBv1 if true
    [bool]$EnableSMB2 = $true,              # Enable SMBv2 if true
    [bool]$EnableSMB3 = $true               # Enable SMBv3 if true
)

# Read endpoints from file
$endpoints = Get-Content -Path $EndpointFile

foreach ($endpoint in $endpoints) {
    Write-Host "Updating SMB protocols for $endpoint..."
    try {
        Invoke-Command -ComputerName $endpoint -ScriptBlock {
            Param($DisableSMB1, $EnableSMB2, $EnableSMB3)
            if ($DisableSMB1) {
                Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
            }
            if ($EnableSMB2 -or $EnableSMB3) {
                Set-SmbServerConfiguration -EnableSMB2Protocol $EnableSMB2 -EnableSMB3Protocol $EnableSMB3 -Force
            }
        } -ArgumentList $DisableSMB1, $EnableSMB2, $EnableSMB3
        Write-Host "Successfully updated $endpoint."
    } catch {
        Write-Warning "Failed to update $endpoint: $_"
    }
}
