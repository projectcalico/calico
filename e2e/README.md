# Calico e2e testing

This package contains end-to-end tests for Calico. It produces a test binary that also imports relevant upstream Kubernetes e2e tests (e.g., the networking conformance tests).

To build:

```
make build
```

## Versioning

Each build of the tests is intended for a particular build and version of the code - namely, the same version as the tests. New tests can be safely added to `master` without worry for supporting older versions. Relevant tests or test fixes may be backported to older branches following normal cherry-pick process.

## Conformance testing

A subset of tests within this package are marked as "Conformance" tests using `framework.ConformanceIt`. These tests are intended to function as mainline function verification for any given installation of Calico, and are run as part of CI against a `kind` cluster.

To be marked as `[Conformance]`, a test must typically:

- Run on any platform, and not rely on additional configuration or external resources.
- Be fast (i.e., 15s or less).
- Pass reliably.

It is worth noting that **all** tests should also strive to meet these criteria! But, as the `[Conformance]` suite is run as part of pre-commit CI, keeping this particular suite small, fast, and reliable increases their value.

To run Calico conformance tests against your cluster:

```
KUBECONFIG=<path to kubconfig> ./bin/k8s/e2e.test --ginkgo.focus="sig-calico.*Conformance"
```

## Test workload images

The test workloads pull from public registries (Docker Hub, `registry.k8s.io`, `gcr.io`). On a cluster whose nodes cannot reach those registries, set `E2E_IMAGE_MIRROR` to a registry host that carries the same repository paths, and every workload image is pulled from there instead:

```
E2E_IMAGE_MIRROR=my-registry.example.com KUBECONFIG=<path to kubeconfig> ./bin/k8s/e2e.test
```

Calico's own images are unaffected: they come from the install under test, not from this setting.
