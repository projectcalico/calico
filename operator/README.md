# Calico Operator

This directory contains the Kubernetes operator that manages the lifecycle of a Calico or Calico Enterprise installation on Kubernetes and OpenShift. Each part of an installation gets its own CRD in the `operator.tigera.io` API group, along with a controller that renders the Kubernetes resources for that part, reconciles them, and reports progress through a TigeraStatus.

The operator is built with the [operator-sdk](https://github.com/operator-framework/operator-sdk) and controller-runtime, so it is worth being familiar with those before making changes here.

## Documentation

- [docs/principles.md](docs/principles.md) - the operator's architecture and the reasoning behind it.
- [docs/api_design.md](docs/api_design.md) - conventions for the CRD types in `api/v1`.
- [docs/dev_guidelines.md](docs/dev_guidelines.md) - code structure, code generation, and cherry-picks.
- [docs/common_tasks.md](docs/common_tasks.md) - running the operator against a local cluster, testing, and debugging.

Installation and configuration documentation for users lives at [https://docs.tigera.io/](https://docs.tigera.io/).

## Building and testing

Builds and tests run through the Makefile in this directory:

```
make build
make test
make image
```

Run `make help` for the full list of targets.
