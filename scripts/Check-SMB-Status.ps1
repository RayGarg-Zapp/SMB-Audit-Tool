# File: Check-SMB-Status.ps1
Param(
    [string]$EndpointFile = "endpoints.txt", # File containing list of endpoints
    [string]$OutputFile = "SMBStatusLogs.csv" # Output CSV file
)

# Ensure required modules are imported
Import-Module SmbShare -ErrorAction SilentlyContinue

# Read endpoints from file
$endpoints = Get-Content -Path $EndpointFile

# Initialize results array
$results = @()

foreach ($endpoint in $endpoints) {
    Write-Host "Checking SMB status for $endpoint..."
    try {
        $smbConfig = Invoke-Command -ComputerName $endpoint -ScriptBlock {
            Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, EnableSMB3Protocol
        }

        $results += [PSCustomObject]@{
            Endpoint          = $endpoint
            EnableSMB1Protocol = $smbConfig.EnableSMB1Protocol
            EnableSMB2Protocol = $smbConfig.EnableSMB2Protocol
            EnableSMB3Protocol = $smbConfig.EnableSMB3Protocol
        }
    } catch {
        Write-Warning "Failed to connect to $endpoint: $_"
        $results += [PSCustomObject]@{
            Endpoint          = $endpoint
            EnableSMB1Protocol = "Error"
            EnableSMB2Protocol = "Error"
            EnableSMB3Protocol = "Error"
        }
    }
}

# Export results to CSV
$results | Export-Csv -Path $OutputFile -NoTypeInformation
Write-Host "SMB status exported to $OutputFile."
