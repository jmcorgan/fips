# Install FIPS as a Windows service.
#
# Usage: powershell -File install-service.ps1
# Requires: Administrator privileges

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Check for admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script requires Administrator privileges. Right-click PowerShell and select 'Run as Administrator'."
    exit 1
}

$InstallDir = "$env:ProgramFiles\fips"
$ConfigDir = "$env:ProgramData\fips"

Write-Host "Installing FIPS service..."

# Create directories
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null

# Copy binaries
$Binaries = @("fips.exe", "fipsctl.exe", "fipstop.exe")
foreach ($bin in $Binaries) {
    $src = "$ScriptDir\$bin"
    if (Test-Path $src) {
        Copy-Item $src "$InstallDir\$bin" -Force
        Write-Host "  Installed $bin"
    } else {
        Write-Warning "Missing $bin in $ScriptDir"
    }
}

# Copy wintun.dll if present
if (Test-Path "$ScriptDir\wintun.dll") {
    Copy-Item "$ScriptDir\wintun.dll" "$InstallDir\wintun.dll" -Force
    Write-Host "  Installed wintun.dll"
}

# Install config (preserve existing)
if (-not (Test-Path "$ConfigDir\fips.yaml")) {
    if (Test-Path "$ScriptDir\fips.yaml") {
        Copy-Item "$ScriptDir\fips.yaml" "$ConfigDir\fips.yaml"
        Write-Host "  Installed default config"
    }
} else {
    Write-Host "  Config already exists, preserving"
}

if (-not (Test-Path "$ConfigDir\hosts")) {
    if (Test-Path "$ScriptDir\hosts") {
        Copy-Item "$ScriptDir\hosts" "$ConfigDir\hosts"
    }
}

# Set FIPS_CONFIG environment variable (machine-wide)
[Environment]::SetEnvironmentVariable("FIPS_CONFIG", "$ConfigDir\fips.yaml", "Machine")
Write-Host "  Set FIPS_CONFIG=$ConfigDir\fips.yaml"

# Add install dir to system PATH if not already there
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($machinePath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$machinePath;$InstallDir", "Machine")
    Write-Host "  Added $InstallDir to system PATH"
}

# Install the service (run from install dir so current_exe() points to the right path)
Write-Host "  Registering Windows service..."
Push-Location $InstallDir
& "$InstallDir\fips.exe" --install-service
$exitCode = $LASTEXITCODE
Pop-Location
if ($exitCode -ne 0) {
    Write-Error "Failed to install service"
    exit 1
}

Write-Host ""
Write-Host "FIPS service installed successfully."
Write-Host ""
Write-Host "Edit config:  notepad $ConfigDir\fips.yaml"
Write-Host "Start:        sc start fips"
Write-Host "Stop:         sc stop fips"
Write-Host "Status:       sc query fips"
Write-Host "Uninstall:    powershell -File uninstall-service.ps1"
