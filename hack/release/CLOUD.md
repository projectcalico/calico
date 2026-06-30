# Cloud Operator release tooling

The `hack/release` tool is a single binary that serves both the OSS/enterprise and Calico Cloud
release flows. Calico Cloud behavior lives in `cloud.go` and `internal/versions/cloud.go` and is
activated **at runtime** when `VARIANT=cloud` (there is no separate `-tags cloud` build). Use the
regular release targets with `VARIANT=cloud`:

- `make release VARIANT=cloud` — build a cloud release
- `make release-publish VARIANT=cloud` — publish a cloud release
- `make release-tag VARIANT=cloud RELEASE_TAG=cloud-vX.Y.Z-N` — build + publish a tagged cloud release

`VARIANT=cloud` also switches the built operator image to `gcr.io/tigera-tesla/operator-cloud`
(amd64) and bakes cloud mode into the operator binary (`-X …/pkg/cloud.buildVariant=cloud`), so the
shipped cloud image is immutably cloud (see `pkg/cloud.IsCloudBuild`). When `VARIANT` is unset,
`cloud.go`'s `init()` returns immediately and the enterprise release flow is unchanged.

## Hashreleases

Either with the hashrelease URL or a local pinned components file. (`HASHRELEASE`, `HASHRELEASE_URL`,
`PINNED_COMPONENTS_FILE`, and `CLOUD_REGISTRY` are read from the environment; command-line make
variables are exported to the tool.)

### Using hashrelease URL

```bash
make release VARIANT=cloud HASHRELEASE=true \
  HASHRELEASE_URL="https://<hashrelease-name>.docs.eng.tigera.net" \
  CLOUD_REGISTRY="gcr.io/unique-caldron-775/cnx/"

make release-publish VARIANT=cloud HASHRELEASE=true \
  HASHRELEASE_URL="https://<hashrelease-name>.docs.eng.tigera.net" \
  CLOUD_REGISTRY="gcr.io/unique-caldron-775/cnx/"
```

### Using local pinned components file

```bash
make release VARIANT=cloud HASHRELEASE=true \
  PINNED_COMPONENTS_FILE="/path/to/pinned_components.yml" \
  CLOUD_REGISTRY="gcr.io/unique-caldron-775/cnx/"

make release-publish VARIANT=cloud HASHRELEASE=true \
  PINNED_COMPONENTS_FILE="/path/to/pinned_components.yml" \
  CLOUD_REGISTRY="gcr.io/unique-caldron-775/cnx/"
```

## Release

The release process is the same as the OSS operator, run with `VARIANT=cloud` (e.g.
`make release-tag VARIANT=cloud RELEASE_TAG=cloud-vX.Y.Z-N`).

## How It Works

### Hashrelease process

1. **Pinned components** are downloaded from `HASHRELEASE_URL/pinned_components.yml`
   (or read from a local file via `PINNED_COMPONENTS_FILE`).

2. From the pinned components the tool extracts:
   - `title`: enterprise version (`--enterprise-version`)
   - `release_name`: used to build the image tag
   - `note`: release branch name (`--enterprise-branch`)

3. **Version tag** is generated as `<release_name>-tesla-<short-git-hash>`.
   No `--version` flag is needed for hashreleases.

4. **Build** compiles the operator binary, generates enterprise CRDs from the pinned enterprise
   version, patches the cloud registry into `pkg/components/cloud_images.go`, builds images, and
   verifies the output.

5. **Publish** pushes images to the registry and writes two CI output files under `/tmp/`:
   - `image-tag`: the full version tag
   - `new-hashrelease`: `"True"` or `"False"` indicating if this is a new hashrelease

### Release process

1. **Publish** pushes the image to the registry. It does not create a GitHub release (cloud releases
   are not published on GitHub).

## Environment Variables

Essential environment variables for building and publishing cloud operator releases. Other variables
from the OSS release process may also be used as needed (see `flags.go`).

| Variable                 | Required           | Description                                                |
| ------------------------ | ------------------ | ---------------------------------------------------------- |
| `HASHRELEASE`            | Yes (hashrelease)  | Set to `true` to enable hashrelease mode                   |
| `HASHRELEASE_URL`        | Yes* (hashrelease) | URL hosting `pinned_components.yml`                        |
| `PINNED_COMPONENTS_FILE` | Yes* (hashrelease) | Local path to `pinned_components.yml` (alternative to URL) |
| `CLOUD_REGISTRY`         | No                 | Registry patched into cloud image config                   |

\* One of `HASHRELEASE_URL` or `PINNED_COMPONENTS_FILE` must be set for hashrelease builds.

## Extension Pattern

Cloud-specific behavior is implemented in `cloud.go` via an `init()` (active only when `VARIANT=cloud`)
that updates OSS flag defaults to cloud defaults and wraps the OSS command handlers:

- **`cloudBuildBefore`**: runs before the OSS build `Before` handler — downloads pinned components,
  sets the enterprise version and branch flags, generates the version tag, and switches the image
  name to the dev image for hashreleases.
- **`cloudSetupHashreleaseBuild`**: wraps `setupHashreleaseBuild` — patches the cloud registry into
  `pkg/components/cloud_images.go` before the OSS registry patching runs.
- **`cloudPublishBefore`**: runs before the OSS publish `Before` handler — disables GitHub release
  creation (unsupported for operator-cloud) and re-derives the version tag for hashreleases.
- **`cloudPostPublish`**: wraps `publishImages` — writes CI output files (`image-tag` and
  `new-hashrelease`) to `/tmp/` after a successful publish (hashrelease only).

Cloud-specific flags (`--hashrelease-url`, `--pinned-components`, `--cloud-registry`) are appended
to the relevant OSS commands in the same `init()` call.

## CI Integration

The cloud build/release runs via:
- Semaphore: `.semaphore/push_images_cloud.yml` (GCR push on `master`/`staging`/`release-*`) and
  `.semaphore/release_cloud.yml` (`cloud-v*` tags), promoted from `.semaphore/semaphore.yml`.
- ArgoCI: `.argoci/templates/hashrelease/build-hashrelease.yaml` builds+publishes a cloud image from
  an enterprise hashrelease and exposes `imageTag`/`newHashrelease`.
