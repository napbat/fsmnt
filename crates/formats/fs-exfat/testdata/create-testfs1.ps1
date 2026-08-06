<#
.SYNOPSIS
    Creates an exFAT test filesystem image (testfs1) for fs-exfat crate testing.

.DESCRIPTION
    This script uses WSL to run the bash script that creates a raw exFAT image
    using mkfs.exfat. This produces a proper raw exFAT filesystem without a
    partition table, which is required for the fs-exfat tests.

.NOTES
    Requires WSL with Ubuntu (or similar) installed.
    Will install exfatprogs if not present.
    Must be run with sudo access in WSL.
#>

param(
    [string]$OutputPath = "$PSScriptRoot\testfs1"
)

$ErrorActionPreference = "Stop"

# Check if WSL is available
$wslCheck = wsl --list --quiet 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "WSL is not available. Please install WSL with Ubuntu."
    exit 1
}

Write-Host "Using WSL to create exFAT test filesystem..."

# Convert Windows path to WSL path using proper escaping
$winScriptDir = $PSScriptRoot -replace '\\', '/'
$wslScriptDir = wsl wslpath -u "'$winScriptDir'"

Write-Host "Script directory (WSL): $wslScriptDir"

# Check if mkfs.exfat is installed, install if not
Write-Host "Checking for mkfs.exfat..."
$mkfsCheck = wsl which mkfs.exfat 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing exfatprogs (requires sudo)..."
    wsl sudo apt-get update
    wsl sudo apt-get install -y exfatprogs
}

# Run the bash script
Write-Host "Running create-testfs1.sh..."
wsl bash -c "cd $wslScriptDir && sudo bash create-testfs1.sh"

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "Test filesystem created successfully at: $OutputPath"
} else {
    Write-Error "Failed to create test filesystem"
    exit 1
}
