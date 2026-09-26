# FIPS RPM packaging.
#
# The counterpart of packaging/debian: the same files land in the same places,
# the same group is created, the same config is seeded, and the same two units
# are enabled. Where the two package managers differ, the differences are
# marked below rather than smoothed over.
#
# The binaries are built before rpmbuild runs, by packaging/rpm/build-rpm.sh,
# and this spec packages them. That is how cargo-deb works on the Debian side,
# and it keeps one cargo invocation — with its target directory, features and
# cross-compilation flags — as the only thing that compiles FIPS. So there is
# no %%prep and no %%build here, and `fips_bindir` says where the binaries are.
#
# Dependencies are not listed: rpmbuild derives them from the ELF files, down
# to the glibc and libdbus symbol versions, which is what the Debian side gets
# from "$auto" plus testing/check-deb-depends.sh. An RPM built on a host newer
# than the target therefore *refuses to install* there rather than installing
# and failing to start. rpm derives the glibc requirement from the binaries, so
# what needs checking is the binaries themselves: testing/check-rpm-floor.sh
# reads that requirement out of the finished package and compares it with
# FIPS_GLIBC_FLOOR — see packaging/README.md.

%global fips_group  fips
%global fips_libdir %{_prefix}/lib/fips

# Where build-rpm.sh leaves the binaries and where the source tree is. Both are
# passed with --define; the defaults only exist so `rpmspec -q` can parse this
# file without them.
%{!?fips_bindir: %global fips_bindir %{_sourcedir}/target/release}
%{!?fips_srcdir: %global fips_srcdir %{_sourcedir}}

# NOT "fips". Fedora's namespace already has a package by that name -- an
# OpenGL FITS image viewer (github.com/matwey/fips3), currently 3.4.0 -- and it
# owns /usr/bin/fips. A package named `fips` at 0.6.0 is therefore an *older*
# `fips` to every RPM tool there is, so a routine `dnf upgrade` replaces a
# running mesh node with an image viewer and takes the units with it. That is
# not hypothetical: it happened on a test machine within the hour, silently.
#
# The Debian side has no such collision, which is why only this name differs.
Name:           fips-mesh
Version:        %{?fips_version}%{!?fips_version:0.6.0}
Release:        %{?fips_release}%{!?fips_release:1}%{?dist}
Summary:        Free Internetworking Peering System mesh network daemon

License:        MIT
URL:            https://github.com/jmcorgan/fips
# The source is the working tree, not a tarball: see the header.
Source0:        %{name}-%{version}.tar.gz

# Shipped by systemd, needed by the scriptlets below.
BuildRequires:  systemd-rpm-macros

Requires:       systemd
# The FITS viewer owns /usr/bin/fips, so the two cannot both be installed. rpm
# would refuse on the file conflict anyway; saying so here makes the refusal
# name the problem instead of naming a path.
Conflicts:      fips
# groupadd, used by %%post. openSUSE calls the package `shadow`; the rich
# dependency satisfies both without naming a distribution.
Requires(post): (shadow-utils or shadow)
# Bluetooth (BLE) transport at runtime; the daemon runs without it.
Recommends:     bluez
# fips-firewall.service runs nft(8). Not required: the unit is opt-in and the
# daemon does not need it.
Recommends:     nftables

%description
FIPS is a distributed, decentralized network routing protocol for mesh nodes
connecting over arbitrary transports including UDP, TCP, Ethernet, Tor, and
Bluetooth (BLE). It provides encrypted peer-to-peer connectivity with automatic
key management, TUN-based virtual networking, and .fips DNS resolution.

%prep
# Nothing to unpack: the binaries and the data files come from the working tree.

%build
# Nothing to build: see the header.

%install
install -D -m 0755 %{fips_bindir}/fips          %{buildroot}%{_bindir}/fips
install -D -m 0755 %{fips_bindir}/fipsctl       %{buildroot}%{_bindir}/fipsctl
install -D -m 0755 %{fips_bindir}/fipstop       %{buildroot}%{_bindir}/fipstop
install -D -m 0755 %{fips_bindir}/fips-gateway  %{buildroot}%{_bindir}/fips-gateway

install -D -m 0755 %{fips_srcdir}/packaging/common/fips-dns-setup \
    %{buildroot}%{fips_libdir}/fips-dns-setup
install -D -m 0755 %{fips_srcdir}/packaging/common/fips-dns-teardown \
    %{buildroot}%{fips_libdir}/fips-dns-teardown

# The units are the Debian package's, unmodified. Both packages install the
# binaries to %%{_bindir} and target the same systemd, so a second copy of four
# unit files would only be a second thing to keep in step.
install -D -m 0644 %{fips_srcdir}/packaging/debian/fips.service \
    %{buildroot}%{_unitdir}/fips.service
install -D -m 0644 %{fips_srcdir}/packaging/debian/fips-dns.service \
    %{buildroot}%{_unitdir}/fips-dns.service
install -D -m 0644 %{fips_srcdir}/packaging/debian/fips-firewall.service \
    %{buildroot}%{_unitdir}/fips-firewall.service
install -D -m 0644 %{fips_srcdir}/packaging/debian/fips-gateway.service \
    %{buildroot}%{_unitdir}/fips-gateway.service

install -D -m 0644 %{fips_srcdir}/packaging/debian/fips.tmpfiles \
    %{buildroot}%{_tmpfilesdir}/fips.conf

# The example config is read by %%post, so it is not under %%{_docdir}: minimal
# and container installs path-exclude that directory. Same reasoning as the
# Debian package.
install -D -m 0644 %{fips_srcdir}/packaging/common/fips.yaml \
    %{buildroot}%{_datadir}/fips/fips.yaml.example

install -D -m 0644 %{fips_srcdir}/packaging/common/hosts \
    %{buildroot}%{_sysconfdir}/fips/hosts
install -D -m 0644 %{fips_srcdir}/packaging/common/fips.nft \
    %{buildroot}%{_sysconfdir}/fips/fips.nft

# Drop-in directory for operator nftables rules included by /etc/fips/fips.nft.
# Empty by default; the include glob matches nothing cleanly out of the box.
install -d -m 0755 %{buildroot}%{_sysconfdir}/fips/fips.d

install -D -m 0644 %{fips_srcdir}/docs/design/fips-security.md \
    %{buildroot}%{_docdir}/fips/fips-security.md
install -D -m 0644 %{fips_srcdir}/LICENSE %{buildroot}%{_licensedir}/fips/LICENSE

%post
# Control-socket access is by group membership, so the group exists before the
# daemon can create the socket.
getent group %{fips_group} >/dev/null || groupadd --system %{fips_group}

# Seed /etc/fips/fips.yaml from the shipped example only if it does not already
# exist. The live config is deliberately not a packaged config file: this
# copy-if-absent yields to any operator- or configuration-management-rendered
# file and never clobbers it, and never leaves a .rpmnew beside it either.
if [ ! -e %{_sysconfdir}/fips/fips.yaml ]; then
    install -m 0600 -o root -g root \
        %{_datadir}/fips/fips.yaml.example \
        %{_sysconfdir}/fips/fips.yaml
fi

if [ -d /run/systemd/system ]; then
    systemd-tmpfiles --create %{_tmpfilesdir}/fips.conf >/dev/null 2>&1 || :
fi

# Presets first: a distribution preset that disables these units is applied
# here, though the explicit enable below then overrides it, so the presets have
# the last word only on units this package does not name.
%systemd_post fips.service fips-dns.service

# Then enable the two units the package considers its own: installing FIPS is
# how an operator asks for a mesh node, and a node that is installed but not
# enabled is not one. fips-firewall.service and fips-gateway.service are
# deliberately left alone — both are opt-in, see
# %%{_docdir}/fips/fips-security.md.
#
# On first install only, which is narrower than the Debian postinst: that one
# enables on every configure, so it re-enables a unit an operator has disabled.
# Here a later `systemctl disable fips` survives an upgrade, which is the
# behaviour an operator who disabled it would expect.
#
# Enabled, not started. The Debian postinst starts units only under
# `[ -n "$2" ]`, which holds on an upgrade and never on a fresh install, so a
# first install there leaves the node to the next boot or to the operator.
# Starting here would also mean fips-dns.service — Type=oneshot running
# fips-dns-setup — rewriting the host resolver inside the install transaction,
# against a fips.yaml seeded from the example seconds earlier. An upgrade
# queues a restart of whatever was running, in the try-restart in %%postun
# below.
#
# (A package submitted to Fedora proper would drop the enables too and let the
# distribution's presets decide, which is the policy there. This package is
# built upstream and installed deliberately, so it matches the .deb instead.)
if [ $1 -eq 1 ] && [ -d /run/systemd/system ]; then
    systemctl enable fips.service >/dev/null 2>&1 || :
    systemctl enable fips-dns.service >/dev/null 2>&1 || :
fi

# On upgrade, reapply the firewall ruleset in place, before the daemon is
# restarted by %%systemd_postun_with_restart below -- %%post of the new package
# runs ahead of %%postun of the old one, which is the ordering the Debian
# postinst has. "try" leaves an inactive unit alone, so this never opts a host
# in, and it must be a reload rather than a restart: that unit's ExecStop
# deletes the table, and a restart would leave the mesh interface unfiltered
# in between. A reload that fails leaves the previous ruleset in force, so it
# is reported and the upgrade goes on.
if [ $1 -ge 2 ] && [ -d /run/systemd/system ]; then
    # The unit files this upgrade installed are not loaded yet -- the reload
    # systemd runs from a file trigger comes at the end of the transaction --
    # so without this the reload below would act on the pre-upgrade unit.
    systemctl daemon-reload >/dev/null 2>&1 || :
    if ! systemctl try-reload-or-restart fips-firewall.service >/dev/null 2>&1; then
        echo "fips: reloading fips-firewall.service failed; the ruleset loaded before the upgrade stays in force" >&2
        echo "fips: check /etc/fips/fips.nft and the rules in /etc/fips/fips.d/" >&2
    fi
fi

%preun
# Stops and disables only on the last erase, not on an upgrade.
%systemd_preun fips.service fips-dns.service fips-gateway.service fips-firewall.service

%postun
# Restarts what was running, on upgrade only. fips-gateway.service is in the
# list because a host that opted it in would otherwise keep running the old
# binary; try-restart leaves an inactive unit alone, so listing it opts nobody
# in. fips-firewall.service is not: it is reloaded in %%post above, because
# restarting it would run its ExecStop and delete the table.
#
# Spelled out rather than left to %%systemd_postun_with_restart. That macro is
# expanded at build time, in the image this package is built in, and the EL9
# expansion only *marks* the units -- `systemd-update-helper
# mark-restart-system-units` -- for a file trigger in that distribution's
# systemd package to act on. On a distribution without that trigger the mark is
# written and nothing ever reads it, so an upgrade silently leaves the old
# binary running. try-restart is portable, and is what the macro would have
# reached in the end anyway.
#
# Queued, not waited on. `systemctl try-restart` without --no-block returns
# when the jobs finish, and this scriptlet runs inside the rpm transaction,
# holding dnf's lock: fips-dns.service is Type=oneshot and fips-dns-setup waits
# up to 30 s for fips0, so a daemon that comes back slowly -- or not at all --
# would hold the whole upgrade there. The restart is a request; whether it
# succeeds is the daemon's business and the journal's, not the package
# manager's.
#
# This is also where the RPM deliberately parts from the Debian postinst,
# which waits for each unit it starts with a bounded poll. That bound exists
# because a blocking `systemctl start` under dpkg held apt, and every package
# operation queued behind it, for ever. Queuing the restart avoids the problem
# the bound was written to contain, rather than reimplementing the bound.
if [ $1 -ge 1 ] && [ -d /run/systemd/system ]; then
    systemctl --no-block try-restart fips.service fips-dns.service fips-gateway.service >/dev/null 2>&1 || :
fi

if [ $1 -eq 0 ]; then
    # The runtime directory is not packaged, so nothing else removes it.
    rm -rf /run/fips

    # DNS configuration fips-dns-setup may have written outside the package,
    # one file per backend it picks between. fips-dns-teardown runs on
    # ExecStop and removes the file of the backend recorded in its state file,
    # or all four when the state file is missing; %%systemd_preun stops the unit
    # before rpm gets here, so this is what catches a host where the unit was
    # not running. Each resolver whose file is removed is told to drop it, as
    # the Debian postrm does: otherwise a host erased while fips-dns was stopped
    # keeps sending .fips queries to the daemon's resolver port until that
    # resolver next restarts. rpm has no purge, so this erase branch is the only
    # cleanup that will ever run.
    restart_resolved=0
    if [ -f %{_sysconfdir}/systemd/dns-delegate.d/fips.dns-delegate ]; then
        rm -f %{_sysconfdir}/systemd/dns-delegate.d/fips.dns-delegate
        restart_resolved=1
    fi
    if [ -f %{_sysconfdir}/systemd/resolved.conf.d/fips.conf ]; then
        rm -f %{_sysconfdir}/systemd/resolved.conf.d/fips.conf
        restart_resolved=1
    fi
    if [ "$restart_resolved" = 1 ] && [ -d /run/systemd/system ] \
        && systemctl is-active --quiet systemd-resolved.service; then
        systemctl restart systemd-resolved \
            || echo "fips: warning: could not restart systemd-resolved; restart it to drop the .fips route"
    fi
    if [ -f %{_sysconfdir}/dnsmasq.d/fips.conf ]; then
        rm -f %{_sysconfdir}/dnsmasq.d/fips.conf
        if [ -d /run/systemd/system ] \
            && systemctl is-active --quiet dnsmasq.service; then
            systemctl reload dnsmasq \
                || echo "fips: warning: could not reload dnsmasq; reload it to drop the .fips route"
        fi
    fi
    if [ -f %{_sysconfdir}/NetworkManager/dnsmasq.d/fips.conf ]; then
        rm -f %{_sysconfdir}/NetworkManager/dnsmasq.d/fips.conf
        if [ -d /run/systemd/system ] \
            && systemctl is-active --quiet NetworkManager.service \
            && command -v nmcli >/dev/null 2>&1; then
            nmcli general reload \
                || echo "fips: warning: could not reload NetworkManager; reload it to drop the .fips route"
        fi
    fi
fi

# Note what is *not* here. The Debian postrm removes /etc/fips and the fips
# group on purge — an explicit, separate operator action. rpm has no purge, so
# the equivalent code would run on an ordinary erase and take the node's
# identity keys with it, including during a distribution upgrade that erases
# and reinstalls. Config and keys therefore survive an erase; remove
# /etc/fips yourself if you mean it.

%files
%dir %{_licensedir}/fips
%license %{_licensedir}/fips/LICENSE
%dir %{_docdir}/fips
%doc %{_docdir}/fips/fips-security.md
%{_bindir}/fips
%{_bindir}/fipsctl
%{_bindir}/fipstop
%{_bindir}/fips-gateway
%dir %{fips_libdir}
%{fips_libdir}/fips-dns-setup
%{fips_libdir}/fips-dns-teardown
%{_unitdir}/fips.service
%{_unitdir}/fips-dns.service
%{_unitdir}/fips-firewall.service
%{_unitdir}/fips-gateway.service
%{_tmpfilesdir}/fips.conf
%dir %{_datadir}/fips
%{_datadir}/fips/fips.yaml.example
%dir %{_sysconfdir}/fips
%dir %{_sysconfdir}/fips/fips.d
%config(noreplace) %{_sysconfdir}/fips/hosts
%config(noreplace) %{_sysconfdir}/fips/fips.nft

%changelog
* Sat Sep 19 2026 Johnathan Corgan <johnathan@corganlabs.com>
- Packaging for RPM-based distributions, translated from the Debian recipe.
