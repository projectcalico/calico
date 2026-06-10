# WS-E: Two-tier fan-out (leader → tier-1 → tier-2 → clients)

## Goal

For the highest scales (target 1M nodes): a single leader is the only
datastore watcher; a small elected set of **tier-1** Typhas connect directly
to the leader; all remaining (**tier-2**) Typhas connect to tier-1; Felix and
other clients connect to tier-2 — except they always prefer a Typha on their
own node, whatever its tier, to smooth bootstrap.

```
            datastore (kube-apiserver)
                      │ (watch, ×1)
                  [ leader ]            ← Lease slot L
                ┌────┼────┐
            [t1-a] [t1-b] [t1-c]        ← Lease slots 1..N (N ≈ 3-10)
           ╱   │  ╲   ...   ╱  │ ╲
        [t2 ×  hundreds of typhas]      ← everyone else
        ╱│╲      ...        ╱│╲
     felix/confd clients (×1M)
```

## Required reading

- `plans/hierarchical-typha/00-overview.md`
- `plans/hierarchical-typha/02-leader-election.md` (Elector wrapper — must be
  instantiable per-lease)
- `plans/hierarchical-typha/03-promotion-demotion.md` (role manager, pod
  self-labelling, leader Service — this WS generalises all three)
- `typha/pkg/discovery/discovery.go` — local-first ordering (~227-275),
  `WithNodeAffinity` (~123), `WithPostDiscoveryFilter` (~129)
- `felix/daemon/daemon.go:331-343` — Felix's discoverer setup (where client
  preference changes land)
- `typha/pkg/k8s/rebalance.go` — `CalculateMaxConnLimit()` (~88-110): the
  connection-limit math assumes "all typhas serve all nodes" and must become
  tier-aware
- `charts/calico/templates/calico-typha.yaml`

## Design

### Electing the leader + N tier-1 slots

client-go leader election is strictly single-leader-per-Lease (verified — no
N-backups concept upstream). Standard pattern: **one Lease per slot**.

- Leases: `calico-typha-leader`, `calico-typha-tier1-0` …
  `calico-typha-tier1-<N-1>`, N from config
  (`Tier1Count`, default 0 = single-tier M2 behaviour).
- Each Typha runs a **slot acquirer** built on the WS-B `Elector` (one elector
  per lease, candidacy gated so a Typha holds at most one slot):
  - Try to acquire the leader lease and all tier-1 leases (shuffled order to
    spread acquisition); on first acquisition, withdraw candidacy for all
    other slots (cancel those electors).
  - On losing the held slot → resume candidacy for all slots.
  - Holding leader slot ⇒ role LEADER. Holding a tier-1 slot ⇒ role TIER1.
    Else ⇒ role TIER2.
- Verify the WS-B wrapper supports cheap cancel/restart per-lease; client-go
  electors are independent objects so this composes. Watch the API-server
  write load: each candidate elector retries every RetryPeriod — with
  hundreds of tier-2 typhas all candidating on N+1 leases this is
  (typhas × slots / RetryPeriod) lease GETs. Mitigate: tier-2 typhas back off
  candidacy when slots are full (watch the Leases; only actively campaign for
  leases whose holder looks expired). This "lazy candidacy" is the one piece
  of nonstandard election code — isolate and UT it well. Alternative
  considered: leader appoints tier-1 by writing a ConfigMap — simpler API
  load profile but invents a bespoke coordination protocol and a single
  point of appointment; rejected in favour of leases + lazy candidacy.

### Role manager generalisation

WS-C's two-state machine becomes three roles; the source-swap mechanics are
unchanged (still "stop source → OnTyphaConnectionRestarted → start source"):

| Role | Sources | Serves |
|---|---|---|
| LEADER | real datastore syncers | tier-1 typhas + same-node clients (who-connects is policed **client-side**, see below — no server-side knob) |
| TIER1 | syncclient → leader Service | tier-2 typhas + same-node clients |
| TIER2 | syncclient → tier-1 Service | felix/confd/etc clients |

Tier advertisement (generalises WS-C's labelling):

- Pod template labels every typha `projectcalico.org/typha-tier: "2"`.
- On acquiring a slot, patch own label to `"leader"` / `"1"`; on demotion
  patch back to `"2"`.
- Services (chart):
  - `calico-typha-leader`: selector tier=leader (WS-C already added).
  - `calico-typha-tier1`: selector tier=1.
  - `calico-typha` (existing, what Felix discovers): **unchanged — keeps
    selecting all typhas.** Decision (Shaun): who-may-connect-to-the-leader is
    policed client-side, not by Service membership. The per-tier Services
    double as the tier-information channel for clients (EndpointSlices don't
    expose pod labels, so clients learn tiers by cross-referencing the tier
    Services' endpoints against the main Service's).
  - On promotion out of tier-2, existing off-node client connections don't
    move by themselves: actively drain them via the existing graceful
    mechanisms (`TerminateRandomConnection` loop — reuse
    `handleGracefulShutDown`'s drain logic without process exit). Dropped
    clients re-discover and land per the client-side policy below; a dropped
    same-node client just reconnects to the same typha.

### Client (Felix) connection preference

Policy (decided, see overview):

1. A client on the same node as a typha always prefers that typha — **whatever
   its tier, including the leader**. This smooths bootstrap: the node's local
   typha is always usable.
2. An off-node client is **forbidden** from connecting to the leader or tier-1
   in larger clusters; it may only use tier-2.
3. "Larger clusters": forbid when tiering is active (`Tier1Count > 0`). In
   single-tier M2 deployments (small/medium clusters) off-node clients may use
   any typha, leader included — its extra load is negligible there.

Implementation: extend `typha/pkg/discovery` to watch the tier Services in
addition to the primary service and classify each endpoint
(leader/tier-1/tier-2/unknown). Ordering/filtering: same-node endpoints first
(any tier), then — if tiering active — only tier-2 endpoints, shuffled.
Endpoints of unknown tier (label/Service lag) count as tier-2 to fail open.
Felix-side config: nothing new — it inherits via the shared discovery package;
gate on a new FelixConfiguration field only if a user-visible toggle is wanted
(open question; default to automatic).
- Typha tier-2's own upstream discovery: `calico-typha-tier1` service,
  same-node preference is *not* wanted between typha tiers (anti-affinity
  spreads them anyway) — plain shuffled.
- Bootstrap edge: brand-new cluster, no tier labels patched yet ⇒
  `calico-typha` (tier=2 selector) matches all pods (label from template) ⇒
  Felix can connect even before the hierarchy settles. Good. Verify the
  label-patch RBAC and ordering don't create a window where a service has no
  endpoints (PodDisruptionBudget + debounce in role manager help).

### Rebalancing / connection-limit math

`CalculateMaxConnLimit` divides expected connections by typha count from the
single service. Per-tier now:

- tier-2 typhas: expected clients ≈ nodes × syncer types ÷ (#tier-2 typhas).
- tier-1: expected ≈ #tier-2 × 4 ÷ #tier-1.
- leader: ≈ #tier-1 × 4.

Parameterise `PollK8sForConnectionLimit` by the serving tier (count pods by
tier label). Keep headroom logic. UT each formula.

### Sizing guidance (for docs + defaults)

1M nodes, 200 clients/typha ⇒ ~5,000 tier-2 typhas ⇒ ~20,000 upstream
connections ÷ tier-1 ⇒ N=100 tier-1 at 200 conns each, leader serves 400
(4 syncer types × 100). Defaults should express ratios, not absolutes;
document the math in DESIGN.md and make `Tier1Count` operator-set for now.
(Auto-scaling tier-1 from node count is a possible follow-up.)

## Tasks

1. Multi-slot acquirer with lazy candidacy (UT with fake clientset: N+1
   leases, M candidates ⇒ exactly one holder each, ≤1 slot per candidate,
   failover on holder death, candidacy back-off verified by API call
   counting).
2. Role manager: three roles, per-role upstream selection, client-drain on
   leaving tier-2.
3. Tier labelling + Services + values-gated selector change + RBAC +
   `gen-manifests`.
4. Discovery: multi-service precedence + same-node-any-tier preference;
   UTs for ordering.
5. Rebalance math per tier + UTs.
6. Metrics: per-role gauge, per-tier connection counts, upstream identity.
7. fv-tests: three-level in-process chain (datastore-fed leader → tier-1 →
   tier-2 → client) with full parity + checksum assertions; kill each level
   and assert recovery (leader death = worst case: tier-1 re-elects leader
   among themselves? **No** — any typha may win the leader lease, including a
   tier-2; test both).
8. Felix FV: small two-tier topology (1 leader + 1 tier-1 + 2 tier-2 + 2
   felixes incl. one co-located with the leader to test own-node preference).
9. DESIGN.md: topology, slot election, sizing math, failure analysis
   (leader death, tier-1 death, partition between tiers).

## Acceptance criteria

- With `Tier1Count=2`, 5 typhas self-organise into 1+2+2; Felix connects only
  to tier-2 (unless co-located); killing any single typha (incl. leader)
  recovers without client-visible outage beyond resync.
- `Tier1Count=0` reproduces M2 behaviour exactly.
- API-server lease traffic from idle candidates bounded (measured in UT/FV by
  call counting) — document the per-typha steady-state QPS.

## Open questions

- Tier-1 auto-sizing from node count — follow-up.
- Whether Felix needs a visible config knob for the preference change or it
  rides the hierarchy gate — confirm during implementation.
