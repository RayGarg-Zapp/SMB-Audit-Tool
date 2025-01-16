# File: Check-SMB-Status.ps1
Param(
    [string]$EndpointFile = "data/endpoints.txt", # File containing list of endpoints
    [string]$OutputFile = "data/SMBStatusLogs.csv" # Output CSV file
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

        $destinationIP = Resolve-DnsName -Name $endpoint -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress
        $hostname = $env:COMPUTERNAME  # Assuming local execution; adjust as needed
        $sourceIP = Test-Connection -ComputerName $endpoint -Count 1 | Select-Object -ExpandProperty IPV4Address

        $results += [PSCustomObject]@{
            Endpoint          = $endpoint
            SourceIP          = $sourceIP
            DestinationIP     = $destinationIP
            Hostname          = $hostname
            ServicePort       = 445  # Default SMB port
            EnableSMB1Protocol = $smbConfig.EnableSMB1Protocol
            EnableSMB2Protocol = $smbConfig.EnableSMB2Protocol
            EnableSMB3Protocol = $smbConfig.EnableSMB3Protocol
        }
    } catch {
        Write-Warning "Failed to connect to $endpoint: $_"
        $results += [PSCustomObject]@{
            Endpoint          = $endpoint
            SourceIP          = "Error"
            DestinationIP     = "Error"
            Hostname          = "Error"
            ServicePort       = "Error"
            EnableSMB1Protocol = "Error"
            EnableSMB2Protocol = "Error"
            EnableSMB3Protocol = "Error"
        }
        Add-Content -Path "data/ErrorLog.txt" -Value "Failed to connect to $endpoint: $_"
    }
}

# Export results to CSV
$results | Export-Csv -Path $OutputFile -NoTypeInformation
Write-Host "SMB status exported to $OutputFile."
