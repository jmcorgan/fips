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
    cargo build --release
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

  # Upgrade: stop the service first, or the installer fails
  # copying fips.exe after it has already changed the config
  # directory. Then rerun the installer and start the service.
  sc.exe stop fips
  powershell -File install-service.ps1
  sc.exe start fips

  # Manage
  sc.exe start fips
  sc.exe stop fips

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
  The service reads C:\ProgramData\fips\fips.yaml, where
  install-service.ps1 puts it, and keeps hosts, peers.allow,
  peers.deny and, with node.identity.persistent: true, fips.key
  beside it. Edit fips.yaml there before starting the service.

  install-service.ps1 creates empty peers.allow and peers.deny
  there, which allow every peer until you add entries. To clear
  a list, empty the file; do not delete it. While either file
  is missing from C:\ProgramData\fips, the service still reads
  that file from \etc\fips on the system drive, where earlier
  releases kept it and any local user can create it. The
  installer stops if it finds a file there with none in
  C:\ProgramData\fips: review that file, move it into
  C:\ProgramData\fips or delete it, and run install-service.ps1
  again.

  install-service.ps1 restricts C:\ProgramData\fips to SYSTEM
  and Administrators before writing into it. Reading or editing
  files there, fipsctl keygen, fipsctl address with no argument,
  and a foreground fips.exe run that relies on
  C:\ProgramData\fips\fips.yaml all need an elevated prompt.
  Unelevated, a foreground run may skip that file without
  saying so, or may fail with an access error.

  A foreground run takes -c <file>, or reads
  \etc\fips\fips.yaml on the current drive, then
  C:\ProgramData\fips\fips.yaml and then, as per-user overrides
  the service does not read, %APPDATA%\fips\fips.yaml,
  %USERPROFILE%\.fips.yaml and .\fips.yaml. The key file sits
  beside the last config loaded. \etc\fips\fips.yaml was the
  system config of earlier releases, and any local user can
  create it; the daemon warns when it loads it, and from v0.6.0
  the search no longer looks there. Move what you need from it
  into C:\ProgramData\fips\fips.yaml and delete it.

  A service that earlier releases ran from \etc\fips reads
  only C:\ProgramData\fips once install-service.ps1 has run,
  so it loses that config and may come up with a new identity.
  The installer stops if it finds \etc\fips\fips.key with no
  fips.key in C:\ProgramData\fips. If the key is this node's,
  move it there, carry the settings you need from
  \etc\fips\fips.yaml, node.identity.persistent: true among
  them, into C:\ProgramData\fips\fips.yaml, delete
  \etc\fips\fips.yaml, and run the installer again. If you did
  not put the key there, delete it.

  fipsctl keygen writes to C:\ProgramData\fips by default and
  needs an elevated prompt. Run install-service.ps1 before it:
  a directory that keygen creates first carries
  C:\ProgramData's access until the installer restricts it.

  A file moved into C:\ProgramData\fips keeps its old
  permissions. That includes a fips.yaml or fips.key moved from
  %APPDATA%\fips as the daemon's warning suggests, so run
  install-service.ps1 again after moving files there.

Logs:
  The service logs to C:\ProgramData\fips\fips.log, rolled at
  10 MiB with four old files kept. A foreground run logs to the
  console.
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
