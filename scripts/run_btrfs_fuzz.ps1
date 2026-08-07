<#
.SYNOPSIS
Runs the Btrfs libFuzzer target with the MSVC AddressSanitizer runtime.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 2147483647)]
    [int]$Runs = 100000,

    [ValidateRange(44, 2147483647)]
    [int]$MaxLength = 131072
)

$ErrorActionPreference = 'Stop'

$visualStudioRoot = Join-Path $env:ProgramFiles 'Microsoft Visual Studio'
$runtime = Get-ChildItem -Path $visualStudioRoot `
    -Recurse `
    -Filter 'clang_rt.asan_dynamic-x86_64.dll' `
    -ErrorAction SilentlyContinue |
    Where-Object {
        $_.DirectoryName -match 'VC\\Tools\\MSVC\\[^\\]+\\bin\\Hostx64\\x64$'
    } |
    Sort-Object -Property FullName -Descending |
    Select-Object -First 1

if ($null -eq $runtime) {
    throw 'The x64 MSVC AddressSanitizer runtime is not installed.'
}

$asanDirectory = $runtime.DirectoryName
$env:Path = "$asanDirectory;$env:Path"
$workspaceRoot = Split-Path -Parent $PSScriptRoot

Push-Location $workspaceRoot
try {
    & cargo +nightly fuzz run btrfs_parser `
        --fuzz-dir crates/fsmnt-fuzz `
        -- "-runs=$Runs" "-max_len=$MaxLength"
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}
finally {
    Pop-Location
}
