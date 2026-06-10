# WS-D: Snapshot integrity checking (incremental datastore checksum)

## Goal

With data now flowing through multiple Typha hops and through the
promotion/demotion reconciliation path, add an end-of-resync (and periodic)
integrity check: the server tells the client a checksum of its current
datastore snapshot; the client compares against a checksum computed over its
own reconstructed state. Mismatch ⇒ the hop dropped/duplicated/corrupted
something (e.g. a dedupe-buffer reconciliation bug) ⇒ alert + remediate.

Hop-by-hop by design: each link (leader↔tier-1, typha↔typha, typha↔felix)
validates independently. That localises faults and avoids requiring identical
byte representations across software versions (see "version skew" below).

## Required reading

- `plans/hierarchical-typha/00-overview.md` (binding decision 2 — protocol
  negotiation rules)
- `typha/pkg/syncproto/sync_proto.go` — full package doc ("Upgrading the
  Typha protocol" section is the law here), `SerializedUpdate`,
  `MsgSyncStatus`, hello structs
- `typha/pkg/snapcache/cache.go` — `publishBreadcrumb()` (~367-481; note it
  already fetches the **old value** for each incoming key at ~424-439 — the
  exact hook a subtract-then-add rolling checksum needs), `Breadcrumb` struct
  (~483-496)
- `typha/pkg/syncserver/sync_server.go` — handshake (~964-1028), delta send
  loop (~1141-1280), snapshot send (~1282-1358), binary-snapshot path
  (`snap_precalc.go`)
- `typha/pkg/syncclient/sync_client.go` — message loop (~491-599)
- `libcalico-go/.../dedupebuffer/dedupe_buffer.go` — where client-side
  tracking could live for Felix-bound checking

## Design

### Checksum definition

Order-independent incremental checksum over the set of live KVs:

- Per-entry digest: `h(entry) = H(len(key) ‖ key ‖ value)` where `key` is
  `SerializedUpdate.Key` (string) and `value` is `SerializedUpdate.Value`
  (the JSON bytes as carried on the wire). 64-bit output.
- Store checksum: combine per-entry digests with **XOR** (or addition mod
  2^64 — pick one, document it). Both support O(1) add/remove:
  - insert key: `cs ^= h(new)`
  - clobber key: `cs ^= h(old); cs ^= h(new)` (per the requirement: subtract
    the old entry before adding the new — the old value is already in hand in
    `publishBreadcrumb`)
  - delete key: `cs ^= h(old)`
- Keys are unique in the store and the key is part of the digest, so XOR
  cancellation between distinct live entries requires a 64-bit collision —
  acceptable for an integrity (not security) check. Hash choice: prefer
  `github.com/cespare/xxhash/v2` if already in the module graph (check
  `go.mod`/`go.sum`; it is a common transitive dep), else stdlib FNV-1a 64.
  Pin the choice in the protocol doc — both sides must agree forever (or
  version it in the hello).
- Also track `KVCount` alongside; cheap and catches gross errors with a much
  better error message than a hash mismatch.

### Server side: maintain on the snapcache, snapshot it on the Breadcrumb

- `snapcache.Cache` keeps `checksum uint64` + `count int`, updated in
  `publishBreadcrumb()` next to the existing old-value comparison. Note the
  existing code *skips* writes where old == new (dedupe) — skipped writes must
  not touch the checksum (they don't change state). Deletions of absent keys:
  no-op.
- Each `Breadcrumb` carries the checksum+count as of that breadcrumb. This
  gives every point-in-time snapshot a consistent checksum that the
  per-client goroutines can read without locks (breadcrumbs are immutable).
- Caveat to verify: confirm the value bytes stored in the B-tree are exactly
  the bytes later written to the wire for both the streaming path and the
  pre-serialized binary-snapshot path (`snap_precalc.go`) — the checksum must
  describe what the client actually receives. (It does — both iterate the
  same breadcrumb KVs — but verify no path mutates `SerializedUpdate.Value`.)

### Protocol carriage

- Hello negotiation: `MsgClientHello.SupportsChecksum bool`;
  `MsgServerHello.SupportsChecksum bool`. Only send checksum data when the
  peer advertised support (gob zero-value rule makes this safe — see
  sync_proto.go doc).
- New message `MsgChecksum { Checksum uint64; KVCount int64 }` (new type ⇒
  must be negotiated). Sent by the server:
  1. immediately after `MsgSyncStatus(InSync)` at the end of initial sync —
     stream position makes it unambiguous which state it describes;
  2. thereafter, whenever the delta-send loop finishes sending the deltas of a
     breadcrumb, at most once per `ChecksumInterval` (default ~30s) — again,
     stream position ties it to "after applying everything sent so far".
     Hook: `sendDeltaUpdatesToClient()` already walks breadcrumb-by-breadcrumb;
     attach the breadcrumb's checksum after its deltas. **Gotcha:** that loop
     coalesces deltas across breadcrumbs when the client lags — only emit the
     checksum of the *last* breadcrumb included in a coalesced batch.
- Do not touch `MsgSyncStatus` (old clients decode it; adding fields is
  gob-safe but keeping a separate negotiated message is cleaner and keeps the
  no-new-fields-on-old-messages discipline simple).

### Client side

Two consumers, staged:

1. **Typha-as-client (this WS, required):** a follower Typha's own snapcache
   independently maintains the same rolling checksum over its B-tree (same
   code, shared helper). On receiving `MsgChecksum`, the follower can't
   compare *instantly* (the deltas it just received are still flowing through
   dedupe buffer → validator → cache), so comparison is deferred: tag the
   expectation and compare once the pipeline has drained past it. Simplest
   correct mechanism: inject a marker through the pipeline (the dedupe buffer
   and decoupler preserve order) and compare when it pops out the far end; or
   compare lazily on the next quiescent moment and only alarm if a mismatch
   persists across N consecutive checks (recommended: persist-across-3-checks
   to avoid false alarms from in-flight skew; a real divergence is permanent
   so persistence filtering is sound).
2. **Felix and other syncclient consumers (follow-up, optional):** Felix has
   no value-preserving store to checksum (dedupe buffer tracks keys, not
   values). Add an opt-in checksum tracker in the syncclient layer: maintain
   `map[key]uint64` of per-entry digests computed from wire bytes
   (~8B + key overhead per KV — fine even at 500k KVs). Same
   persist-across-N comparison. Ship behind config; default off for Felix
   initially.

**Version-skew caveat (important):** an intermediate Typha deserializes
values and re-serializes them (`SerializeUpdate`) into its own cache. With
identical code versions the bytes are identical (deterministic Go JSON
marshalling of the same struct), but across versions the serialized form can
legitimately differ (added fields, etc.). The hop-by-hop comparison is between
*my cache as server* and *my client's reconstruction of it*, so each
comparison spans a single client/server pair: the wire bytes the client hashes
ARE the server's bytes... **except** the typha-as-client deferred comparison
above compares the follower's *re-serialized* cache against the upstream's
checksum. Mitigation: when `MsgServerHello.Version != our version`, downgrade
mismatch handling to KVCount-only (counts survive re-serialization). Spell
this out in DESIGN.md and implement the downgrade.

### Mismatch handling

- Always: log (with both checksums, counts, syncer type, upstream identity) +
  Prometheus counter `typha_checksum_mismatches_total{syncer_type=...}` and
  gauge for last-compare status.
- Remediation (config `ChecksumMismatchAction`, default `reconnect`):
  `log` | `reconnect`. Reconnect = treat as connection failure → existing
  restart path (`OnTyphaConnectionRestarted` reconciliation) gives a clean
  re-sync. Rate-limit: max one forced reconnect per ~10min per pipeline to
  avoid mismatch-loops melting the hierarchy; after that, `log` + unready?
  (No — keep serving; just alarm. Document.)

## Tasks

1. Shared checksum helper package (`typha/pkg/synccheck` or inside
   `syncproto`): per-entry digest + rolling combine; golden-vector UTs.
2. snapcache integration: maintain checksum/count; expose on Breadcrumb; UTs
   incl. clobber, delete-absent, dedupe-skip paths; fuzz/property test:
   random op sequence ⇒ checksum equals recompute-from-scratch.
3. Protocol: hello flags, `MsgChecksum`, server send points (initial InSync +
   periodic, coalescing-aware); register new type with gob
   (see `init()` in sync_proto.go).
4. Typha-as-client deferred comparison + mismatch handling + metrics + config.
5. (Optional/follow-up PR) syncclient generic tracker for Felix.
6. fv-tests: chained typhas with checksums on — clean run shows matches;
   fault-injection test (deliberately corrupt follower cache via test hook)
   shows detection + reconnect-remediation.
7. Version-skew test: old-client-flag-off ⇒ no MsgChecksum sent (existing
   fv-tests back-compat pattern, see `CreateClientNoDecodeRestart`).
8. DESIGN.md: checksum algorithm, carriage, skew downgrade, remediation.

## Acceptance criteria

- Zero false positives across the full WS-A/WS-C fv-test suites with
  checksumming enabled (run promotion/demotion storms with checksum
  verification active — this doubles as the strongest regression test for
  WS-C's reconciliation).
- Injected corruption detected within one ChecksumInterval and remediated.
- Old clients (no flag) see no new message types.

## Open questions

- Enable periodic checksum by default once stable, or keep opt-in? (Plan:
  on-by-default for typha↔typha once M2 soak is clean; opt-in for Felix.)
- 64-bit vs 128-bit digest. 64 is fine for alerting; if we ever auto-repair
  based on it, revisit.
