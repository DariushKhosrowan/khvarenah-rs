# Security Policy

DastYab is a circumvention tool. A weakness here can expose users who face
real consequences for being identified, so reports are taken seriously and
handled quietly.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private reporting:

<https://github.com/DastYab/dastyab/security/advisories/new>

If that is not reachable from where you are, open a public issue containing
only the words "security contact request" and no technical detail; a private
channel will be arranged.

Please include: affected component (crate and module), version, what an
attacker gains, and a minimal reproduction if you have one.

## What is in scope

- The worker bundle and its session-secret gate (`X-DastYab-Session`)
- The DNS-tunnel protocol, its ARQ, and the auth seal
- Token storage and file permissions under `~/.dastyab`
- The DTN gossip bundle signing and the trust ledger
- The self-updater and the release asset path
- Anything that leaks a real client IP or identity past a proxy

## What is out of scope

- Denial of service against your own machine or your own worker
- Weaknesses in an upstream proxy engine (xray, sing-box, tor) — report those
  upstream, though a note is welcome if DastYab misuses them
- The fact that a Cloudflare Workers deployment is attributable to the
  Cloudflare account that created it; that is inherent to the model
- Social engineering, or physical access to an unlocked machine

## Handling

Reports are acknowledged within a few days. Fixes ship in a patch release with
a `SECURITY.md`-linked changelog entry that describes the class of bug without
publishing an exploit recipe. Reporters are credited unless they ask not to be.

## Supported versions

The latest released minor version receives security fixes. Older artefacts on
the release page are superseded and may predate the current name and protocol
identifiers.
