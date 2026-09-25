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
| `VERSION` | The operator version to publish, `X.Y.Z`. The bundle pins `$(DEV_REGISTRY)/operator:v$(VERSION)` by digest, so that tag must already be pushed. |
| `PREV_VERSION` | The version this one replaces, `X.Y.Z`, or `0.0.0` for none. |
| `CHANNEL` | The OperatorHub channel, which must be a `release-v3.YY` branch name. Defaults to the current branch when that branch is one; from any other branch, pass it explicitly. |
| `DEFAULT_CHANNEL` | Optional. Only set it when the channel should become the package default. |
| `DEV_REGISTRY` | Optional. The registry the operator image is pinned from. Defaults to `calico` (Docker Hub); pass `DEV_REGISTRY=quay.io/calico` to pin the Quay image. |
| `BUNDLE_OPENSHIFT_VERSIONS` | Optional. The `com.redhat.openshift.versions` range, e.g. `v4.19-v4.22`. The default in `gen-bundle` moves with each release; a bundle only reaches the catalog of an OpenShift version inside this range. |

Output:

```
bundle/bundle-v<VERSION>.Dockerfile   # builds the bundle image
bundle/<VERSION>/manifests/           # CSV + CRDs
bundle/<VERSION>/metadata/            # annotations.yaml
```

`make bundle` pulls and inspects the operator image, so it runs docker on the
host — the build container has no docker-in-docker.

## The catalog decides the upgrade graph, not the bundle

Each `catalog-templates/v4.XX.yaml` in the certified-operators repo is an
`olm.template.basic` template, with hand-written channel entries and a
`defaultChannel`. Those entries decide who upgrades to what; the bundle's
`spec.replaces` and `DEFAULT_CHANNEL` do not. Publishing a bundle into a new
channel therefore also needs, in every template for an OpenShift version the
bundle supports:

- a `release-v3.YY` channel block with an entry for the new bundle, and
- `defaultChannel` moved to it, if it should become the default.

**The first bundle built from this repo** is a move off the `release-v1.YY`
channels that tigera/operator published into, which top out at
`tigera-operator.v1.42.2`. Build it with `PREV_VERSION=1.42.2`, not the previous
Calico version, which was never published as a bundle. Its channel entry
should `replace` `tigera-operator.v1.42.2`; the `olm.skipRange` of
`<VERSION>` already covers every 1.x bundle.

## What runs, in order

`make bundle` is four targets, each depending on the one before it, so running
any one of them runs the steps ahead of it too:

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
unit tests run by `make -C operator hack/gen-bundle/ut` (and by `make ci`). Both
of its commands take their paths from flags (`--repo-root`, `--operator-dir`)
that default to running from `operator/`, so pass them when running it by hand
from anywhere else.

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
