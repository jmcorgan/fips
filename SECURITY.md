# Security Policy

FIPS is a permissionless mesh: any node can peer with any other, and
every node processes traffic from parties it has never met. Defects in
that path are the ones we most want to hear about, and we would rather
hear about them privately first.

## Reporting a vulnerability

**Email <johnathan@corganlabs.com>.** Please do not open a public issue
for a suspected vulnerability, and please do not post one to a Nostr
relay or a chat channel before we have had a chance to respond.

Useful things to include, none of them required:

- The commit hash or release tag the finding is against. FIPS moves
  quickly across three branches, so a finding without a ref can be
  expensive to place.
- The file and line you read, and what you read there. A claim we can
  open and check ourselves is worth several we have to reconstruct.
- Whether you walked the path from an attacker-reachable entry point to
  the defect, or inferred it. Both are welcome; knowing which saves time.
- What an attacker needs: on-path position, an admitted peering
  relationship, a signature from a key the node accepts, or nothing but
  the ability to send a packet.
- Any harness or tooling output, if the finding came from a scanner. Say
  so either way; it changes how we read the citations, not whether we
  take them seriously.

Findings produced with automated or AI-assisted tooling are in scope and
welcome. We ask only that you tell us what was machine-generated and what
you checked yourself.

## What to expect

We will acknowledge a report within a few days and tell you whether we
think the finding holds, in our own words, per item. Where we disagree
with a severity we will say why rather than silently reclassifying it.
Where a report is right and we had missed it, we will say that too.

We do not run a bug bounty and cannot offer payment. We are glad to
credit you in the changelog and the release notes for the fix, under
whatever name or handle you prefer, and equally glad not to if you would
rather stay anonymous.

## Disclosure

We would like to agree on timing with you rather than impose it. Our
default is that a finding stays private until a fix is released on the
affected branches, and that we do not sit on it indefinitely: if a fix is
going to take a long time, we would rather say so and agree a date than
let the clock run quietly.

Please tell us in your report if you have a disclosure deadline in mind.
If we have not responded at all within two weeks, treat that as a failure
on our side and escalate however you see fit.

## Scope

In scope is anything in this repository: the `fips` daemon and its
libraries, the control socket and CLI, the packaging under
[packaging/](packaging/), and the CI workflows.

Some things are known and accepted rather than undiscovered, and a report
about them will get a pointer to the reasoning rather than a fix:

- The protocol is not stable and has not had an independent cryptographic
  audit. Wire format and session behavior still change between minor
  versions.
- The control socket authenticates by filesystem permission and, on
  platforms without a Unix domain socket, by loopback binding. Where that
  assumption is weaker than a local user boundary, it is documented at the
  implementation.
- A node that you have admitted as a peer is trusted to the extent the
  protocol says it is. Findings about what an *admitted* peer can do are
  still interesting; they are just a different class from what a stranger
  can do, and it helps if you say which one you mean.

Denial of service against a node by simply sending it a lot of traffic is
not a finding. Amplification, where a small input costs the node or a
third party a large amount, is.

## Supported versions

Fixes land on the oldest branch they apply to and are merged upward, so a
fix for the maintenance line reaches all three.

| Branch   | Version line | What it receives                        |
| -------- | ------------ | --------------------------------------- |
| `maint`  | 0.4.x        | Security and bug fixes                  |
| `master` | 0.5.x        | Security and bug fixes, plus new work   |
| `next`   | 0.6.x        | Development, including wire-format work |

Released versions before the current maintenance line do not receive
fixes. If you are running one, the fix will be to upgrade.

## Security documentation

[docs/reference/security.md](docs/reference/security.md) describes the
security posture as built, and
[docs/design/fips-security.md](docs/design/fips-security.md) covers the
design reasoning behind it. Both are worth reading before reporting, but
neither is a prerequisite: we would rather have a duplicate report than a
missing one.
