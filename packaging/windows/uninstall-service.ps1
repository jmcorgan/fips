# Uninstall the FIPS Windows service.
#
# Usage: powershell -File uninstall-service.ps1 [-RemoveAll]
# Requires: Administrator privileges
#
# By default preserves config in %ProgramData%\fips\.
# Pass -RemoveAll to remove config and identity keys too.

param(
    [switch]$RemoveAll
)

$ErrorActionPreference = "Stop"

# Check for admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script requires Administrator privileges. Right-click PowerShell and select 'Run as Administrator'."
    exit 1
}

$InstallDir = "$env:ProgramFiles\fips"
$ConfigDir = "$env:ProgramData\fips"

Write-Host "Uninstalling FIPS service..."

# Stop the service if running
$svc = Get-Service -Name "fips" -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Host "  Stopping service..."
    Stop-Service -Name "fips" -Force
}

# Uninstall the service
if (Test-Path "$InstallDir\fips.exe") {
    Write-Host "  Removing service registration..."
    & "$InstallDir\fips.exe" --uninstall-service
}

# Remove binaries
if (Test-Path $InstallDir) {
    Write-Host "  Removing $InstallDir"
    Remove-Item -Recurse -Force $InstallDir
}

# Remove from PATH
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($machinePath -like "*$InstallDir*") {
    $newPath = ($machinePath -split ";" | Where-Object { $_ -ne $InstallDir }) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
    Write-Host "  Removed from system PATH"
}

# Remove FIPS_CONFIG env var
[Environment]::SetEnvironmentVariable("FIPS_CONFIG", $null, "Machine")

# Config removal
if ($RemoveAll) {
    if (Test-Path $ConfigDir) {
        Write-Host "  Removing config and keys at $ConfigDir"
        Remove-Item -Recurse -Force $ConfigDir
    }
} else {
    if (Test-Path $ConfigDir) {
        Write-Host "  Preserving config at $ConfigDir"
    }
}

Write-Host ""
Write-Host "FIPS service uninstalled."
if (-not $RemoveAll) {
    Write-Host "Config preserved at $ConfigDir (use -RemoveAll to delete)"
}
