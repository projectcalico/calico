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

> **Editing this file:** a design doc records the design, not the
> change that introduced it. The default is **no edit**; when one is
> warranted it is normally one to three lines in a section that is
> already there. See [`design/MAINTAINING.md`](../design/MAINTAINING.md).

## Cross-cutting

- Combined `calico` binary, restart-on-config-change, health
  reporting, build system: see the root
  [`DESIGN.md`](../DESIGN.md).
- Felix's view of Typha (the consumer side) is documented in
  [`felix/DESIGN.md`](../felix/DESIGN.md) §1 under the data
  flow / lifecycle sections.

## Gaps

This doc is currently a stub. Sections to flesh out as the
content grows: fan-out architecture and connection management,
the snapshot+delta protocol Felix consumes, scaling
characteristics, configuration surface.
