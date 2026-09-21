# OpenShift operator bundle

This directory is the **output** of `make bundle`. Everything in it apart from
this README is generated and git-ignored (see `operator/.gitignore`).

A bundle is the artifact Red Hat certifies and OperatorHub serves: a
ClusterServiceVersion (CSV), the CRDs the operator owns, and a small metadata
directory, packaged into an image.

## Build one

```bash
make -C operator bundle VERSION=3.34.0 PREV_VERSION=3.33.0 CHANNEL=release-v3.34
```

| Variable | Meaning |
|---|---|
| `VERSION` | The operator version to publish, `X.Y.Z`. The bundle pins `quay.io/calico/operator:v$(VERSION)` by digest, so that tag must already be pushed. |
| `PREV_VERSION` | The version this one replaces, `X.Y.Z`, or `0.0.0` for none. |
| `CHANNEL` | The OperatorHub channel, which must be a `release-vX.YY` branch name. Defaults to the current branch. |
| `DEFAULT_CHANNEL` | Optional. Only set it when the channel should become the package default. |

Output:

```
bundle/bundle-v<VERSION>.Dockerfile   # builds the bundle image
bundle/<VERSION>/manifests/           # CSV + CRDs
bundle/<VERSION>/metadata/            # annotations.yaml
```

`make bundle` pulls and inspects the operator image, so it runs docker on the
host — the build container has no docker-in-docker.

## What runs, in order

`make bundle` is four targets:

1. **`bundle-generate`** — depends on `bundle-manifests`, which runs
   `gen-bundle get-manifests` to stage, under
   `build/_output/bundle/<VERSION>/`, the manifests and CRDs that
   `operator-sdk generate bundle` reads. It then runs `operator-sdk generate
   bundle`, which merges the static CSV base with the staged deployment, RBAC
   and CRDs.
2. **`update-bundle`** — runs `gen-bundle update-bundle`, which moves the
   generated output under `bundle/<VERSION>/` and writes the values that are
   only knowable at build time.
3. **`bundle-validate`** — `operator-sdk bundle validate`, against the full
   `operatorframework` suite rather than only the required checks, because this
   bundle is built to be certified.
4. **`bundle-image`** — `docker build` of the generated Dockerfile.

`gen-bundle` is a Go program in [`../hack/gen-bundle`](../hack/gen-bundle), with
unit tests run by `make -C operator hack/gen-bundle/ut` (and by `make ci`).

## Where each piece comes from

**Static CSV fields** —
[`config/manifests/bases/tigera-operator.clusterserviceversion.yaml`](../config/manifests/bases/tigera-operator.clusterserviceversion.yaml).
Description, icon, links, maintainers, provider, keywords, install modes,
categories, the certification feature annotations, and the owned-CRD
descriptions all live there. If you find yourself adding a constant to
`gen-bundle`, it belongs in the base instead.

**Staged manifests** — `gen-bundle get-manifests` copies them out of the working
tree, so a bundle carries the manifests it was built alongside:

| Staged as | Source |
|---|---|
| `deploy/operator.yaml` | `manifests/ocp-tigera-operator-no-resource-loading.yaml` |
| `deploy/role.yaml`, `deploy/rolebinding-tigera-operator.yaml` | `manifests/ocp/` |
| `deploy/` sample CRs | `manifests/ocp/03-cr-installation.yaml`, `operator/config/samples/operator_v1_imageset.yaml` |
| `crds/` operator CRDs | `operator/pkg/crds/operator/` |
| `crds/` Calico CRDs | `libcalico-go/config/crd/` |

The sample CRs become the CSV's `alm-examples` annotation — what OperatorHub
offers in its "Create instance" forms. The Installation example is the OpenShift
install-time CR itself, so what OperatorHub offers and what the install
instructions tell users to apply cannot drift apart.

**Build-time values** — written by `gen-bundle update-bundle`: the digest-pinned
operator image (in both `relatedImages` and the embedded deployment), the build
timestamp, the version, `replaces`, `olm.skipRange`, the per-architecture
`operatorframework.io/arch.*` labels, the display name, and the capability
level.

## Things that will bite you

- **The CSV base's `metadata.name` must be `tigera-operator.v<semver>`**,
  matching `--package`. `operator-sdk` silently discards a base whose name does
  not parse that way and substitutes a placeholder CSV — every field in the base
  is lost, with no error.
- **Keep three lists in sync**: `calicoResources` in
  [`../hack/gen-bundle/manifests.go`](../hack/gen-bundle/manifests.go), the
  owned CRDs in the CSV base, and the `internal-objects` annotation in that same
  base. A CRD staged but not described raises a validation warning; a CRD
  described but not staged is advertised by the CSV without being installed.
- **`capabilities` is set by `gen-bundle`, not the base** (`--capabilities`,
  default `Basic Install`). It is the level we are certified against, so raising
  it should be a deliberate act rather than a one-line edit to a YAML file.
- **`relatedImages` cannot live in the base** — `operator-sdk` does not carry it
  over. Any image that has to be listed goes in
  [`../hack/gen-bundle/update.go`](../hack/gen-bundle/update.go).
- **`config/samples/kustomization.yaml` must only list files that exist**, or
  `kustomize build config/samples` fails and takes bundle generation with it.
- **`operator_v1_imageset.yaml` is deliberately inert.** It is a published
  example, so its name must not match a variant the operator looks for — see the
  comment at the top of that file.
