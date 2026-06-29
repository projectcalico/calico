# Node — Architecture

The node container orchestrates Calico's per-node lifecycle: it
bootstraps the node, installs the CNI plugin, and runs the
per-node daemons (Felix, confd, BIRD) under runit inside a
single container.

- **Role.** A single multi-process container deployed as a
  DaemonSet on every cluster node. It is the entry point for
  Calico on the node — kubelet starts it, and it owns
  everything from CNI plugin installation through dataplane
  programming.
- **Contents.** Runs Felix (dataplane agent), confd
  (configuration templater), and BIRD (BGP daemon). Each lives
  as a runit service under
  `node/filesystem/etc/service/available/<name>/run` and is
  dispatched via the combined `calico` binary (see root
  [`DESIGN.md`](../DESIGN.md) → Combined `calico` binary).
- **Startup.** `node/pkg/lifecycle/startup/startup.go` is the
  startup entry point — it provisions the node's resources in
  the datastore (Node resource, BGP peers, etc.) before the
  per-node daemons take over.
- **CNI plugin installation.** The node container drops the
  CNI plugin binary and configuration into the host's CNI
  directories so kubelet can invoke it for pod-network setup.

## Cross-cutting

- Combined `calico` binary, restart-on-config-change, health
  reporting, build system: see the root
  [`DESIGN.md`](../DESIGN.md).
- Dataplane details (eBPF / iptables / nftables / Windows)
  live in [`felix/DESIGN.md`](../felix/DESIGN.md) and the
  per-topic sub-designs under [`felix/design/`](../felix/design/).

## Keep this doc in sync with the code

A PR that changes how the node container works — startup
sequence, runit service set, CNI plugin installation path, or
any documented invariant — must update this file in the same
PR. Exemptions: bug fix restoring documented behaviour,
mechanical refactor with no observable change, comment /
log-message edits, dependency bumps. If in doubt, update.

This doc is currently a stub. Sections to flesh out as the
content grows: startup flow detail (datastore-side resource
provisioning, lock semantics), runit service supervision and
restart semantics, CNI plugin installation and upgrade flow,
BGP integration via BIRD/confd.
