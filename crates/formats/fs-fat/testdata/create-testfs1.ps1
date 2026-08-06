<#
.SYNOPSIS
    Creates a FAT32 test filesystem image (testfs1) for fs-fat crate testing.

.DESCRIPTION
    This script uses WSL to run the bash script that creates a raw FAT32 image
    using mkfs.fat. This produces a proper raw FAT32 filesystem without a
    partition table, which is required for the fs-fat tests.

.NOTES
    Requires WSL with Ubuntu (or similar) installed.
    Will install dosfstools if not present.
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

Write-Host "Using WSL to create FAT32 test filesystem..."

# Convert Windows path to WSL path using proper escaping
$winScriptDir = $PSScriptRoot -replace '\\', '/'
$wslScriptDir = wsl wslpath -u "'$winScriptDir'"

Write-Host "Script directory (WSL): $wslScriptDir"

# Check if mkfs.fat is installed, install if not
Write-Host "Checking for mkfs.fat..."
$mkfsCheck = wsl which mkfs.fat 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing dosfstools (requires sudo)..."
    wsl sudo apt-get update
    wsl sudo apt-get install -y dosfstools
}

# Run the bash script
Write-Host "Running create-testfs1.sh..."
wsl bash -c "cd '$wslScriptDir' && sudo bash create-testfs1.sh"

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "Test filesystem created successfully at: $PSScriptRoot\testfs1"
} else {
    Write-Error "Failed to create test filesystem"
    exit 1
}
