<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->

# Typha client and discovery

Applies to: `typha/pkg/syncclient/**`, `typha/pkg/discovery/**`,
`typha/pkg/syncclientutils/**`, `typha/pkg/tlsutils/**`.

The client library turns a Typha connection back into the local
[Syncer API](../../design/syncer/DESIGN.md): the consumer hands
`syncclient.New` its `api.SyncerCallbacks` and receives exactly
the calls an in-process syncer would have made. Consumers:
Felix (`felix/daemon/daemon.go`, wired directly), and — via the
`syncclientutils.MustStartSyncerClientIfTyphaConfigured` helper,
which falls back to an in-process syncer when Typha isn't
configured — confd's BGP client and the `node` tunnel-IP and
node-status helpers. Each requests its `SyncerType` in the
handshake ([`protocol.md`](./protocol.md)).

## The client (`pkg/syncclient`)

`SyncerClient` runs the client side of the protocol: hello
exchange, decoder restarts (rebuilding its gob decoder, with
snappy when negotiated, and ACKing before the server continues),
prompt `MsgPong` replies, and decoding `MsgKVs` back into
`[]api.Update` batches for `OnUpdates`. Per-message read/write
deadlines protect it from a hung server; the server's pings are
what keep the read deadline fed when the datastore is quiet.

**Reconnection is the consumer's choice.** A dropped connection
means a full resync — new handshake, fresh snapshot — because the
server keeps no per-client state to resume from. The client
reconnects automatically only if the callbacks implement
`RestartAwareCallbacks` (`OnTyphaConnectionRestarted`), i.e. only
if the consumer can reconcile a fresh snapshot against what it
already applied. `dedupebuffer.DedupeBuffer` (see
[`design/syncer/DESIGN.md`](../../design/syncer/DESIGN.md))
implements this — it diffs the new snapshot against the keys it
had, synthesizing deletions for anything that vanished during the
gap — which is how Felix and the other consumers ride out Typha
restarts and rebalancing drops without restarting themselves.
Without restart-aware callbacks the client just finishes, and the
consumer restarts the process (`MustStartSyncerClientIfTyphaConfigured`
does `log.Fatal`; a component restart is an acceptable, if
heavyweight, resync).

## Discovery (`pkg/discovery`)

Typha runs behind a regular Kubernetes Service, but clients do
**not** connect through the ClusterIP: the `Discoverer` lists the
Service's EndpointSlices and picks a specific, `Ready` backend, so
that retries actually move between Typhas and the server-side
connection counting stays meaningful. Ordering:

1. **Typhas on the client's own node first** (`WithNodeAffinity`).
   This is a WireGuard bootstrap measure: if a rebooted node has a
   stale WireGuard keypair, its traffic to *other* nodes may
   blackhole — including to remote Typhas — while a same-node
   Typha is reachable without crossing the wire. Felix connects
   locally, learns the current datastore state, repairs its
   WireGuard config, and thereby unblocks its own (and inbound)
   cross-node connections. Felix layers a post-discovery filter
   on top for the same reason (its WireGuard bootstrap logic in
   `felix/daemon/daemon.go`).
2. **Random shuffle within each group**, so a herd of restarting
   clients spreads across the fleet instead of piling onto one
   Typha.

`ConnectionAttemptTracker` iterates candidates without repeats
and **re-runs discovery between attempts** — during a rolling
upgrade the endpoint set changes under the client, and retrying
stale addresses wastes the (deliberately long, see
[`server.md`](./server.md)) connection timeouts. The attempt
budget is sized from the discovered fleet (2× headroom) before
the client gives up.

## TLS

When configured (recommended; required by the shipped manifests'
Felix↔Typha setup), the connection is mutual TLS: the server
requires and verifies a client certificate, and both sides check
the peer's identity — Common Name and/or URI SAN (SPIFFE-style)
— against configuration, either matching if both are set. The
client deliberately sets `InsecureSkipVerify` and does chain
verification plus the identity check itself
(`tlsutils.CertificateVerifier`): Go's default verification binds
the certificate to the dialled hostname/IP, but Typha addresses
are ephemeral pod IPs from EndpointSlices; identity here means
"is a genuine Typha/Felix", not "owns this IP".

## Review notes

- The client must remain a *thin* protocol adaptor: no caching,
  no filtering, no reordering — semantics belong in the server
  (shared by all clients) or in the consumer's callbacks. Its
  output must be a valid Syncer stream.
- Anything that changes reconnection behaviour must keep the
  restart-aware contract: `OnTyphaConnectionRestarted` fires
  before any update from the new connection, and a consumer that
  isn't restart-aware must never be silently reconnected (it
  would double-apply the snapshot).
- Discovery changes must preserve: `Ready`-only endpoints,
  local-node preference (the WireGuard bootstrap depends on it),
  shuffling (herd dispersal), and re-discovery between attempts.
- Client-side timeout changes follow the same doctrine as the
  server's ([`server.md`](./server.md)): at scale, premature
  give-up is worse than slow success.

## Keep this doc in sync

A PR that changes client behaviour, discovery/selection, or the
TLS identity model must update this file in the same PR.
