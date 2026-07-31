---
name: kind-cluster
description: Create, deploy to, reload, and tear down a local kind cluster running Calico from locally-built images. Use when the user wants to bring up a test cluster, try a change on a real cluster, reload a rebuilt image onto kind, or destroy the cluster.
---

# Kind Cluster Development

Kind targets are defined in `lib.Makefile` and orchestrated from the root
`Makefile`. Scripts and infrastructure live in `hack/test/kind/`, with cluster
config, Helm values, and supporting manifests under `hack/test/kind/infra/`.

Run all of these from the repo root.

```bash
make kind-up                # Build all images + create cluster + deploy Calico (full bringup)
make kind-cluster-create    # Create the kind cluster (no images, no Calico)
make kind-build-images      # Build all container images needed for the kind cluster
make kind-deploy            # Load images + install Calico via Helm + wait for readiness
make kind-reload            # Reload only changed images onto an existing cluster (incremental)
make kind-cluster-destroy   # Tear down the kind cluster
make kind-down              # Alias for kind-cluster-destroy
```

Image loading is incremental: `kind-reload` and `kind-deploy` compare local
Docker image IDs against what is already on the cluster and only transfer the
ones that changed. So the normal edit/test loop is `make -C <component> build`
followed by `make kind-reload`, not a full `kind-up`.

Override the cluster name with `KIND_NAME=<name>` if you need more than one
cluster at a time.
