<#
.SYNOPSIS
    Creates an NTFS test filesystem image (testfs1) for fs-ntfs crate testing.

.DESCRIPTION
    This script uses WSL to run the bash script that creates a raw NTFS image
    using mkntfs. This produces a proper raw NTFS filesystem without a partition
    table, which is required for the fs-ntfs tests.

.NOTES
    Requires WSL with Ubuntu (or similar) installed.
    Will install ntfs-3g if not present.
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

Write-Host "Using WSL to create NTFS test filesystem..."

# Convert Windows path to WSL path using proper escaping
$winScriptDir = $PSScriptRoot -replace '\\', '/'
$wslScriptDir = wsl wslpath -u "'$winScriptDir'"

Write-Host "Script directory (WSL): $wslScriptDir"

# Check if ntfs-3g is installed, install if not
Write-Host "Checking for ntfs-3g..."
$mkntfsCheck = wsl which mkntfs 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing ntfs-3g (requires sudo)..."
    wsl sudo apt-get update
    wsl sudo apt-get install -y ntfs-3g
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
