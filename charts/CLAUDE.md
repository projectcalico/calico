# Helm Charts — Operational Guide

After editing chart templates, run `make gen-manifests` from the repo root. It
regenerates the `manifests/` directory, which is otherwise entirely generated —
never hand-edit it. Commit the chart change and the regenerated manifests
together.

## The READMEs drift silently

The install and upgrade instructions in
[`tigera-operator/README.md`](./tigera-operator/README.md) and
[`crd.projectcalico.org.v1/README.md`](./crd.projectcalico.org.v1/README.md) are
hand-written, so nothing catches them going stale.

A chart change that alters how a user installs or upgrades Calico via Helm must
update the matching README in the same PR. That includes: moving resources
between charts, adding or removing a manual step, renaming a chart, and changing
a documented values key or example command.

See [`.github/instructions/helm-charts.instructions.md`](../.github/instructions/helm-charts.instructions.md).
