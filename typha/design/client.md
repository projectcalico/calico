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
`syncclient.New` its `api.SyncerCallbacks` and receives a stream
equivalent to an in-process syncer's (Typha may reorder and
coalesce, within the API's eventual-consistency contract).
Consumers: Felix (`felix/daemon/daemon.go`, wired directly), and
— via the `syncclientutils.MustStartSyncerClientIfTyphaConfigured`
helper, which falls back to an in-process syncer when Typha isn't
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
`RestartAwareCallbacks` (`OnTyphaConnectionRestarted`), i.e. can
reconcile a fresh snapshot against what they already applied.
`dedupebuffer.DedupeBuffer` (see
[`design/syncer/DESIGN.md`](../../design/syncer/DESIGN.md))
implements this — it diffs the new snapshot against the keys it
had, synthesizing deletions for anything that vanished — which is
how Felix and the other consumers ride out Typha restarts without
restarting themselves. Otherwise the client just finishes and the
consumer restarts the process
(`MustStartSyncerClientIfTyphaConfigured` does `log.Fatal`; a
component restart is an acceptable, if heavyweight, resync).

## Discovery (`pkg/discovery`)

Typha runs behind a regular Kubernetes Service, but clients do
**not** connect through the ClusterIP: the `Discoverer` lists the
Service's EndpointSlices and picks a specific, `Ready` backend, so
that retries actually move between Typhas, the server-side
connection counting stays meaningful, and Calico doesn't depend on
kube-proxy. Ordering:

1. **Typhas on the client's own node first** (`WithNodeAffinity`).
   This is a WireGuard bootstrap measure: a rebooted node with a
   stale WireGuard keypair may blackhole traffic to *other* nodes
   — including remote Typhas — while a same-node Typha is
   reachable without crossing the wire. Felix connects locally,
   learns the current state, repairs its WireGuard config, and
   unblocks its cross-node traffic. (Felix layers a
   post-discovery filter on top for the same reason — its
   WireGuard bootstrap logic in `felix/daemon/daemon.go`.)
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

When configured (the operator install enforces TLS and mints the
certificates automatically; manifest installs don't, but we
recommend setting it up manually), the connection is mutual TLS:
the server requires and verifies a client certificate, and both
sides check the peer's identity — Common Name and/or URI SAN
(SPIFFE-style) — against configuration, either matching if both
are set. The
client deliberately sets `InsecureSkipVerify` and does chain
verification plus the identity check itself
(`tlsutils.CertificateVerifier`): Go's default verification binds
the certificate to the dialled hostname/IP, but Typha addresses
are ephemeral pod IPs from EndpointSlices; identity here means
"is a genuine Typha/Felix", not "owns this IP".

## Review notes

- The client is a thin protocol adaptor: caching and filtering
  live in the server (shared by all clients) or in the consumer's
  callbacks. (The reconnection caching may move inside the client
  one day; today it's outside, in `dedupebuffer`.) Its output must
  be a valid Syncer stream.
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
