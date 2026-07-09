---
applyTo:
  - "typha/**"
---

# Typha

Architecture, invariants, and review criteria for Typha live in
the design index [`typha/DESIGN.md`](../../typha/DESIGN.md) and
the per-topic sub-designs under
[`typha/design/`](../../typha/design/):

- [`protocol.md`](../../typha/design/protocol.md) —
  `typha/pkg/syncproto/**` and any change to what goes on the
  wire.
- [`server.md`](../../typha/design/server.md) —
  `typha/pkg/{daemon,calc,snapcache,syncserver,k8s,config}/**`.
- [`client.md`](../../typha/design/client.md) —
  `typha/pkg/{syncclient,discovery,syncclientutils,tlsutils}/**`.

Before writing code (Copilot coding agent) or reviewing a PR
(Copilot code review) in any file matched by this instruction's
`applyTo`:

1. Read the matching sub-design(s) and apply the review notes
   embedded at the end of each section.
2. Typha proxies the Syncer API; its output must remain a valid
   Syncer stream. The API contract is in
   [`design/syncer/DESIGN.md`](../../design/syncer/DESIGN.md) —
   follow that link for any change that filters, coalesces, or
   transforms the update stream.
3. Pay particular attention to: the protocol back-compat rules
   (never send unnegotiated message types; frozen
   `gob.RegisterName` names; ACK-before-new-format), the
   breadcrumb-cache publish ordering and safe-approximation
   doctrine, and the timeout doctrine (at scale, false-positive
   disconnects are worse than slow recovery).

Follow links — the designs reference siblings, the shared syncer
design, and code.

## Doc update rule

The repo-wide doc-update rule and its exemptions
([`.github/copilot-instructions.md` → Documentation map](../copilot-instructions.md),
mirrored in [`.claude/CLAUDE.md`](../../.claude/CLAUDE.md)) apply.
For Typha, "changes how it works" means: a wire-protocol or
handshake change; a change to cache/pipeline semantics, snapshot
handling, timeouts, or connection governance; or a change to
client discovery/reconnection behaviour. Update the relevant
sub-design under [`typha/design/`](../../typha/design/) (and the
index [`typha/DESIGN.md`](../../typha/DESIGN.md) if the table or
overview changes) in the same PR.
