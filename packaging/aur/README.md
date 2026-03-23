# AUR Publication Guide for FIPS

This directory contains Arch Linux packaging files for two AUR packages:

- **`fips`** -- release package, builds from a tagged GitHub tarball
- **`fips-git`** -- development package, builds from latest git master

## Overview

### Files in This Directory

| File | Purpose |
|------|---------|
| `PKGBUILD` | Release package build script (builds from tagged tarball) |
| `PKGBUILD-git` | Git development package build script (builds from latest master) |
| `fips.install` | Pacman post-install/post-upgrade messaging |
| `fips.sysusers` | sysusers.d fragment (creates `fips` system group) |
| `fips.tmpfiles` | tmpfiles.d fragment (creates `/run/fips/`) |
| `fips.service` | Symlink to `../debian/fips.service` |
| `fips-dns.service` | Symlink to `../debian/fips-dns.service` |

Both PKGBUILDs reference files from `packaging/debian/` (service files) and
`packaging/common/` (config files) at build time. These are pulled from the
source tree during `package()`, not from this directory.

## Local Build and Validation

Build and validate the `-git` package locally using the Makefile target:

```sh
make -C packaging aur
```

This runs `makepkg -sf` followed by `namcap` on the resulting package.

For manual testing of individual steps:

```sh
# Build the -git package (uses local git clone, no network download needed)
cd packaging/aur
makepkg -sf -p PKGBUILD-git

# Lint the built package
namcap fips-git-*.pkg.tar.zst

# Lint the PKGBUILD itself
namcap PKGBUILD-git
```

The `-git` variant builds from the local git clone, so no network download is
needed for the source. The release PKGBUILD requires a tagged release tarball
on GitHub to build and cannot be tested without one.

## Prerequisites for AUR Publication

### 1. AUR Account

Register at <https://aur.archlinux.org/register/> using the maintainer email
(`jcorgan@corganlabs.com`).

### 2. SSH Key

Generate a dedicated ed25519 key for AUR access:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/aur -C "jcorgan@corganlabs.com" -N ""
```

### 3. SSH Config

Add the following to `~/.ssh/config`:

```text
Host aur.archlinux.org
    IdentityFile ~/.ssh/aur
    User aur
```

### 4. Register the Key with AUR

1. Copy the public key contents:
   ```sh
   cat ~/.ssh/aur.pub
   ```
2. Go to <https://aur.archlinux.org> -> My Account -> SSH Public Key
3. Paste the public key and save

### 5. Test the Connection

```sh
ssh -T aur@aur.archlinux.org
```

This should print a welcome message or your username. If it hangs or
returns "Permission denied", verify that the key was added correctly.

## Initial Push -- fips-git Package

Follow these steps exactly. Each command is concrete and copy-pasteable.

### Step 1: Clone the AUR Repo

Cloning an AUR repo that does not yet exist creates the package entry:

```sh
git clone ssh://aur@aur.archlinux.org/fips-git.git /tmp/aur-fips-git
```

If the package does not exist yet, this creates an empty repository.

### Step 2: Copy Required Files

From the root of the fips source repository:

```sh
cp packaging/aur/PKGBUILD-git /tmp/aur-fips-git/PKGBUILD
cp packaging/aur/fips.install /tmp/aur-fips-git/
cp packaging/aur/fips.sysusers /tmp/aur-fips-git/
cp packaging/aur/fips.tmpfiles /tmp/aur-fips-git/
```

Only `PKGBUILD`, `.SRCINFO`, and files referenced in `source=()` or `install=`
go into the AUR repo. Service files and config files are NOT copied -- they
come from the source tree at build time via the `source=()` git clone.

### Step 3: Generate .SRCINFO

This step is **critical** -- AUR requires `.SRCINFO` alongside every PKGBUILD:

```sh
cd /tmp/aur-fips-git
makepkg --printsrcinfo > .SRCINFO
```

### Step 4: Commit and Push

```sh
cd /tmp/aur-fips-git
git add PKGBUILD .SRCINFO fips.install fips.sysusers fips.tmpfiles
git commit -m "Initial import of fips-git"
git push
```

### Step 5: Verify

Visit <https://aur.archlinux.org/packages/fips-git> -- the package should
appear within a few seconds of the push.

## Initial Push -- fips Release Package

Same pattern as the `-git` package, but using the release PKGBUILD.

### Step 1: Clone the AUR Repo

```sh
git clone ssh://aur@aur.archlinux.org/fips.git /tmp/aur-fips
```

### Step 2: Copy Files

From the root of the fips source repository:

```sh
cp packaging/aur/PKGBUILD /tmp/aur-fips/PKGBUILD
cp packaging/aur/fips.install /tmp/aur-fips/
cp packaging/aur/fips.sysusers /tmp/aur-fips/
cp packaging/aur/fips.tmpfiles /tmp/aur-fips/
```

### Step 3: Verify the Release PKGBUILD

Before pushing, ensure the PKGBUILD is correct for the current release:

1. Verify `pkgver` matches the latest tagged release (currently `0.1.0`)
2. If the tarball b2sum is a placeholder, download the tarball and compute:
   ```sh
   curl -sL https://github.com/jmcorgan/fips/archive/v0.1.0.tar.gz | b2sum | cut -d' ' -f1
   ```
3. Update the first entry in `b2sums=()` in the PKGBUILD with the real hash

### Step 4: Generate .SRCINFO

```sh
cd /tmp/aur-fips
makepkg --printsrcinfo > .SRCINFO
```

### Step 5: Commit and Push

```sh
cd /tmp/aur-fips
git add PKGBUILD .SRCINFO fips.install fips.sysusers fips.tmpfiles
git commit -m "Initial import of fips 0.1.0"
git push
```

### Step 6: Verify

Visit <https://aur.archlinux.org/packages/fips> -- the package should appear.

## Verification

After both packages are pushed, verify everything works end-to-end.

### Search AUR

```sh
yay -Ss fips
```

Or visit <https://aur.archlinux.org/?K=fips> in a browser.

### Install the Git Variant

```sh
yay -S fips-git
```

### Verify the Installation

```sh
fips --version
fipsctl --version
fipstop --version
systemctl cat fips.service
cat /usr/lib/sysusers.d/fips.conf
cat /usr/lib/tmpfiles.d/fips.conf
```

### Test the Release Variant

On a separate machine or after removing `fips-git`:

```sh
yay -R fips-git
yay -S fips
```

Then run the same verification commands above.

## GitHub Secrets for CI (Phase 4 Preparation)

For automated AUR updates via GitHub Actions, a separate SSH key is needed.

### Step 1: Generate a CI-Specific Key

Generate a **separate** passphrase-less ed25519 key for CI. Do NOT reuse the
personal key from the prerequisites section:

```sh
ssh-keygen -t ed25519 -f /tmp/github-aur -C "github-actions-aur" -N ""
```

### Step 2: Add the Public Key to AUR

AUR supports multiple SSH keys per account. Add the contents of
`/tmp/github-aur.pub` to the AUR account alongside the personal key:

1. Go to <https://aur.archlinux.org> -> My Account -> SSH Public Key
2. Paste the new public key (you can have multiple keys, one per line)

### Step 3: Add the Private Key to GitHub

1. Go to <https://github.com/jmcorgan/fips/settings/secrets/actions>
2. Create a new repository secret named `AUR_SSH_PRIVATE_KEY`
3. Paste the contents of `/tmp/github-aur` (the private key file)

### Step 4: Clean Up Local Key Files

```sh
rm /tmp/github-aur /tmp/github-aur.pub
```

## Updating Packages

### fips-git (Development)

AUR convention is to only push when the PKGBUILD itself changes (new
dependencies, build flags, source URL changes, etc.). Users get new builds
automatically via:

```sh
yay -Syu --devel
```

Do **NOT** push pkgver-only bumps to the AUR -- the `pkgver()` function
handles versioning at build time.

### fips (Release)

Push an update when a new version is tagged. The steps are:

1. Update `pkgver` in the PKGBUILD to the new version
2. Reset `pkgrel` to `1`
3. Recompute the tarball b2sum:
   ```sh
   curl -sL https://github.com/jmcorgan/fips/archive/v<NEW_VERSION>.tar.gz | b2sum | cut -d' ' -f1
   ```
4. Update `b2sums=()` with the new hash
5. Regenerate `.SRCINFO`:
   ```sh
   makepkg --printsrcinfo > .SRCINFO
   ```
6. Commit and push both `PKGBUILD` and `.SRCINFO`

Phase 4 CI automation will handle this workflow automatically on new GitHub
releases.
