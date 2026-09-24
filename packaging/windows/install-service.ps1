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

# Create the install directory
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# Create the config directory, or restrict an existing one, so that only
# SYSTEM and Administrators can use it before anything is written into it.
# The service keeps its identity key, config, hosts file, peer ACL files and
# log there, and the ACL inherited from C:\ProgramData lets any local user
# read those files and create missing ones. A user may also have created the
# directory, or a link in its place, before this script ran, so a link, a
# directory owned by another account, and a link or folder inside it are
# refused rather than acted on. A user who created the directory keeps full
# control of it through an inherited entry even after an administrator takes
# ownership, so the only recovery offered for a refused directory is to
# delete it. Well-known SIDs are used because account names are translated on
# non-English Windows.
$icacls = "$env:SystemRoot\System32\icacls.exe"

# A new object, so only the DACL is written and any explicit entry an
# existing directory carried is dropped; inheritance from C:\ProgramData is
# turned off.
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
$inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
foreach ($sid in @("S-1-5-18", "S-1-5-32-544")) {
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        [System.Security.Principal.SecurityIdentifier]::new($sid),
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inherit,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
}

# A new directory is created with this ACL in one step. Created first and
# restricted afterwards, it would carry C:\ProgramData's access in between,
# and a user could turn the empty directory into a junction in that time.
# Both calls leave an existing directory, or a link at the path, as it is.
# Windows PowerShell's .NET Framework takes the ACL in
# Directory.CreateDirectory; PowerShell 7 takes it in
# FileSystemAclExtensions.CreateDirectory instead.
if ($PSVersionTable.PSEdition -eq "Core") {
    [System.IO.FileSystemAclExtensions]::CreateDirectory($acl, $ConfigDir) | Out-Null
} else {
    [System.IO.Directory]::CreateDirectory($ConfigDir, $acl) | Out-Null
}

$dirItem = Get-Item -LiteralPath $ConfigDir -Force
if ($dirItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
    Write-Error "$ConfigDir is a link or junction, not a directory. Remove it, then run install-service.ps1 again."
    exit 1
}

try {
    $ownerSid = (Get-Acl -LiteralPath $ConfigDir).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
} catch {
    Write-Error "Cannot read the owner of $ConfigDir. Another account may have created it and placed files in it. Copy out anything you need, delete the directory, then run install-service.ps1 again. If Windows refuses the deletion, take ownership first, but still delete it: taking ownership leaves its creator full control of it."
    exit 1
}
$trustedOwners = @("S-1-5-18", "S-1-5-32-544", [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
if ($trustedOwners -notcontains $ownerSid) {
    Write-Error "$ConfigDir is owned by $ownerSid, not by SYSTEM, Administrators or this account. Another account may have created it and placed files in it. Copy out anything you need, delete the directory, then run install-service.ps1 again. If Windows refuses the deletion, take ownership first, but still delete it: taking ownership leaves its creator full control of it."
    exit 1
}

& $icacls $ConfigDir /setowner "*S-1-5-32-544" /L /Q
if ($LASTEXITCODE -ne 0) {
    Write-Error "icacls could not set the owner of $ConfigDir (exit code $LASTEXITCODE). Another account may have changed its permissions. Copy out anything you need, delete the directory, then run install-service.ps1 again."
    exit 1
}

# FIPS keeps only files in the directory. Applying the new ACL propagates
# into existing entries, so links and folders are refused before it as well
# as after it and after each file is reset. An existing directory that is
# still empty can be turned into a junction by any user until the ACL is
# applied, so each check also refuses the directory itself if it has become
# a link.
$refuseEntries = {
    if ((Get-Item -LiteralPath $ConfigDir -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        Write-Error "$ConfigDir became a link or junction while the installer ran. Another account may have converted it, and the permissions of the folder it points to may have been changed. Remove the link, then run install-service.ps1 again."
        exit 1
    }
    foreach ($item in @(Get-ChildItem -LiteralPath $ConfigDir -Force)) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or $item.PSIsContainer) {
            Write-Error "$($item.FullName) is a link or a folder, and FIPS keeps only files in $ConfigDir. Inspect and remove that entry, then run install-service.ps1 again."
            exit 1
        }
    }
}
& $refuseEntries

Set-Acl -LiteralPath $ConfigDir -AclObject $acl

& $refuseEntries

foreach ($item in @(Get-ChildItem -LiteralPath $ConfigDir -Force)) {
    & $icacls $item.FullName /setowner "*S-1-5-32-544" /L /Q
    if ($LASTEXITCODE -ne 0) {
        Write-Error "icacls could not set the owner of $($item.FullName) (exit code $LASTEXITCODE). Another account may have placed or changed this file. Delete the file if it is still there, then run install-service.ps1 again."
        exit 1
    }
    & $icacls $item.FullName /reset /L /Q
    if ($LASTEXITCODE -ne 0) {
        Write-Error "icacls could not reset the ACL of $($item.FullName) (exit code $LASTEXITCODE). Another account may have placed or changed this file. Delete the file if it is still there, then run install-service.ps1 again."
        exit 1
    }
}

& $refuseEntries

Write-Host "  Restricted $ConfigDir to SYSTEM and Administrators"

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
Write-Host "Logs:         $ConfigDir\fips.log"
Write-Host "Start:        sc start fips"
Write-Host "Stop:         sc stop fips"
Write-Host "Status:       sc query fips"
Write-Host "Uninstall:    powershell -File uninstall-service.ps1"
