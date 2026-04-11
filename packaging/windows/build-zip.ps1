# Build a Windows ZIP package for FIPS.
#
# Usage: powershell -File packaging/windows/build-zip.ps1 [-Version <version>] [-NoBuild]
# Output: deploy/fips-<version>-windows-x86_64.zip
#
# Prerequisites: Rust toolchain installed

param(
    [string]$Version = "",
    [switch]$NoBuild
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PackagingDir = Split-Path -Parent $ScriptDir
$ProjectRoot = Split-Path -Parent $PackagingDir

# Derive version from Cargo.toml if not provided
if (-not $Version) {
    $cargoToml = Get-Content "$ProjectRoot\Cargo.toml" -Raw
    if ($cargoToml -match 'version\s*=\s*"([^"]+)"') {
        $Version = $Matches[1]
    } else {
        Write-Error "Could not determine version from Cargo.toml"
        exit 1
    }
}

$Arch = "x86_64"
$PkgName = "fips-$Version-windows-$Arch"
$DeployDir = "$ProjectRoot\deploy"
$StagingDir = "$env:TEMP\fips-staging-$([guid]::NewGuid().ToString('N'))"
$BinaryDir = "$ProjectRoot\target\release"

Write-Host "Building FIPS v$Version for Windows $Arch..."

# Build release binaries
if (-not $NoBuild) {
    Push-Location $ProjectRoot
    cargo build --release --no-default-features --features tui
    if ($LASTEXITCODE -ne 0) {
        Write-Error "cargo build failed"
        exit 1
    }
    Pop-Location
}

# Verify binaries exist
$Binaries = @("fips.exe", "fipsctl.exe", "fipstop.exe")
foreach ($bin in $Binaries) {
    if (-not (Test-Path "$BinaryDir\$bin")) {
        Write-Error "Missing binary: $BinaryDir\$bin"
        exit 1
    }
}

# Create staging directory
New-Item -ItemType Directory -Force -Path $StagingDir | Out-Null

# Copy binaries
foreach ($bin in $Binaries) {
    Copy-Item "$BinaryDir\$bin" "$StagingDir\$bin"
}

# Copy config
Copy-Item "$PackagingDir\common\fips.yaml" "$StagingDir\fips.yaml"
Copy-Item "$PackagingDir\common\hosts" "$StagingDir\hosts"

# Copy helper scripts
Copy-Item "$ScriptDir\install-service.ps1" "$StagingDir\install-service.ps1"
Copy-Item "$ScriptDir\uninstall-service.ps1" "$StagingDir\uninstall-service.ps1"

# Create README
@"
FIPS v$Version for Windows
==========================

Quick Start (foreground mode):
  .\fips.exe -c fips.yaml

Windows Service:
  # Install (requires Administrator)
  powershell -File install-service.ps1

  # Manage
  sc start fips
  sc stop fips

  # Uninstall
  powershell -File uninstall-service.ps1

TUN Support:
  Download wintun.dll from https://www.wintun.net/ and place it
  in the same directory as fips.exe. Running the daemon requires
  Administrator privileges for TUN creation.

Control Socket:
  The control socket uses TCP on localhost:21210.
  fipsctl and fipstop connect to this port automatically.

Configuration:
  Edit fips.yaml before starting. Place it in the same directory
  as fips.exe, or in %APPDATA%\fips\, or set FIPS_CONFIG.
"@ | Out-File -FilePath "$StagingDir\README.txt" -Encoding UTF8

# Create ZIP
New-Item -ItemType Directory -Force -Path $DeployDir | Out-Null
$ZipPath = "$DeployDir\$PkgName.zip"
if (Test-Path $ZipPath) { Remove-Item $ZipPath }
Compress-Archive -Path "$StagingDir\*" -DestinationPath $ZipPath

# Cleanup
Remove-Item -Recurse -Force $StagingDir

Write-Host ""
Write-Host "Package built: deploy\$PkgName.zip"
Write-Host "  Size: $([math]::Round((Get-Item $ZipPath).Length / 1MB, 2)) MB"
Write-Host ""
Write-Host "Extract and run: .\fips.exe -c fips.yaml"
