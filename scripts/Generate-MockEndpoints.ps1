# File: Generate-MockEndpoints.ps1
Param(
    [int]$Count = 1000,                             # Number of endpoints to generate
    [string]$OutputFile = "data/endpoints.txt"      # Output file for endpoints
)

# Create the output directory if it doesn't exist
$dir = Split-Path -Path $OutputFile
if (!(Test-Path $dir)) { 
    New-Item -ItemType Directory -Path $dir -Force
}

# Validate the count parameter
if ($Count -le 0) {
    Write-Error "The number of endpoints must be greater than zero."
    exit 1
}

# Generate endpoints
try {
    1..$Count | ForEach-Object { "Endpoint-$_.domain.com" } | Set-Content -Path $OutputFile
    Write-Host "Successfully generated $Count endpoints in $OutputFile."
} catch {
    Write-Error "Failed to generate endpoints: $_"
    exit 1
}
