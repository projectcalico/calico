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

## Keep this doc in sync with the code

A PR that changes how Typha works — its fan-out behaviour, the
datastore-side connection shape, the Felix-facing protocol, or
any documented invariant — must update this file in the same PR.
Exemptions: bug fix restoring documented behaviour, mechanical
refactor with no observable change, comment / log-message edits,
dependency bumps. If in doubt, update.

This doc is currently a stub. Sections to flesh out as the
content grows: fan-out architecture and connection management,
the snapshot+delta protocol Felix consumes, scaling
characteristics, configuration surface.
