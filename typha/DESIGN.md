# Typha — Architecture

Typha is a fan-out proxy between Felix instances and the
datastore. It exists so that large clusters (typically >50
nodes) can scale without each Felix opening its own datastore
connection.

- **Role.** Sits between Felix instances and the datastore
  (etcd or the Kubernetes API). Connects once upstream, caches,
  and fans the stream out to many downstream Felix instances.
- **Effect.** Reduces datastore load and the number of upstream
  watchers. Datastore latency to Felix becomes
  Typha-amortised rather than per-Felix.
- **Deployment.** Optional but recommended for clusters above
  ~50 nodes. The typical operator-managed deployment runs
  Typha as a DaemonSet or Deployment in front of the datastore.

## Cross-cutting

- Combined `calico` binary, restart-on-config-change, health
  reporting, build system: see the root
  [`DESIGN.md`](../DESIGN.md).
- Felix's view of Typha (the consumer side) is documented in
  [`felix/DESIGN.md`](../felix/DESIGN.md) §1 under the data
  flow / lifecycle sections.

## Sync protocol compression

The Felix-facing sync protocol supports optional compression of the
server-to-client stream (client-to-server messages are small and stay
uncompressed).

- **Negotiation.** The client lists the algorithms it supports (zstd,
  snappy) in its hello message. The server picks the first algorithm
  from its own preference order that the client supports. The default
  order is zstd then snappy: zstd compresses the sync data to roughly
  half the size that snappy manages (see
  [`docs/compression-analysis.md`](docs/compression-analysis.md)), and
  snappy remains as the fallback for older clients. Compression also
  requires the client to support decoder restart; otherwise the stream
  stays uncompressed.
- **Switching invariant.** The server changes the stream encoding only
  via `MsgDecoderRestart`, and it sends no bytes in the new encoding
  until the client ACKs. This guarantees the client can never read
  bytes in one encoding with a decoder for another, no matter how much
  its decoder has buffered.
- **Cached binary snapshots.** For each (syncer type × configured
  algorithm) the server pre-compresses the current snapshot once and
  streams the same bytes to every new client, instead of re-encoding
  per connection. The cached stream ends with an embedded
  `MsgDecoderRestart`; after the client ACKs it, the server starts a
  fresh compressed stream for delta updates on that connection.

## Keep this doc in sync with the code

A PR that changes how Typha works — its fan-out behaviour, the
datastore-side connection shape, the Felix-facing protocol, or
any documented invariant — must update this file in the same PR.
Exemptions: bug fix restoring documented behaviour, mechanical
refactor with no observable change, comment / log-message edits,
dependency bumps. If in doubt, update.

This doc is currently a stub apart from the compression section.
Sections to flesh out as the content grows: fan-out architecture
and connection management, the snapshot+delta protocol Felix
consumes, scaling characteristics, configuration surface.
