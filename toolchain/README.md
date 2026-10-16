# Toolchain images

The images every Calico build and CI step runs in. Each published tag is
immutable: a change to an image's source must move its tag.

## Layout

| Path | What |
|---|---|
| `images/<image>/` | One image: `Dockerfile`, `Makefile`, and its own version files |
| `cmd/` | Go commands shipped in an image: `artifact`, `binfmt`, `scratch-utils`, `disk-image-builder` |
| `internal/` | Their packages. `archutil` (buildkit) and `imager` (Google) are vendored, with their licenses. |
| `lib.mk`, `go.mk` | Build, check, publish and Go helpers every image Makefile includes |
| `vm-images/ci-base/` | The GCE image the CI VM fleet boots |
| `preload-disks/ci-cache/` | The GKE disk that holds calico/go-build pre-pulled |

## Images and tags

| Image | Tag | Version source | Arches |
|---|---|---|---|
| go-build | `<go>-llvm<llvm>[-N]` | Go: root `go.mod`. LLVM and `GO_BUILD_REV`: `metadata.mk` | amd64, arm64, ppc64le, s390x |
| rust-build | `<rust>[-N]` | `RUST_VERSION`, `RUST_BUILD_REV`: `metadata.mk` | all four |
| binfmt | `qemu-v<qemu>[-N]` | `QEMU_VERSION`, `BINFMT_REV`: `metadata.mk` | amd64 |
| tinygo | `<tinygo>[-N]` | `images/tinygo/versions.yaml`, `TINYGO_REV` in its Makefile | amd64, arm64 |
| scratch-utils | `vX.Y` | `images/scratch-utils/versions.env` | amd64 |
| signing-tools | `vX.Y` | `images/signing-tools/versions.env` | amd64 |
| base | `ubi9-<epoch>`, `ubi10-<epoch>` | the time it is published | all four |

The tag is the pin consumers build with: `metadata.mk` derives `GO_BUILD_VER`,
`RUST_BUILD_VER` and `BINFMT_VER`, and nothing restates them. Kubernetes is not
in any image; tests fetch its binaries by `K8S_VERSION`.

## Changing an image

| Change | Edit |
|---|---|
| Go | the `go` line of every `go.mod` (Renovate does this), then `make -C toolchain/images/go-build update-pins` for the Go checksums and `.argoci/config.yaml` |
| LLVM, Rust or QEMU | its version in `metadata.mk` |
| Anything else in an image, a tool bump included | its revision: set `GO_BUILD_REV` and the like to the next `<tag>-N` |
| scratch-utils or signing-tools | the version in its `versions.env` |
| base | nothing: `.argoci/cron/toolchain-base.yaml` republishes it when UBI or its source moves, and Renovate moves `CALICO_BASE_VER` |

A revision names the full tag it applies to, so a version bump resets it
without an edit.

`make -C toolchain/images/<image> check-published` prints `build` or
`published`, and fails when the tag is already published from other source.
That is the check a missed revision trips.

## Building locally

```bash
make -C toolchain/images/go-build image test        # host arch
make -C toolchain/images/go-build image ARCH=s390x  # emulated, registers QEMU first
make -C toolchain/images/go-build print-tag print-source-hash
```

Go runs in `golang:$(GO_VERSION)` from the repo root, so the host needs no Go.

## CI

- **Pull requests** build and test what changed (`.argoci/modules/10-toolchain.yaml`).
  A PR's images go to `gcr.io/unique-caldron-775/ci-toolchain/<image>:<tag>-<source-hash>`,
  never to Docker Hub, and the rest of that PR's CI runs on them.
- **Merges** publish each tag not yet published, one job per arch, then the
  multi-arch manifest (`.argoci/publish/toolchain-images.yaml`). A go-build
  publish also rebuilds the ci-base VM image and the preload disk.
- **Daily**, `.argoci/cron/toolchain-base.yaml` checks UBI for calico/base.

Layers run from least to most likely to change, and timestamps are fixed, so a
Go bump re-pulls only the layers built from Go.
