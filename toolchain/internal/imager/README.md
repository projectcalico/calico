# gke-disk-image-builder (vendored)

Builds a GKE secondary-boot-disk image with container images already unpacked on
it. `../build-preload-disk.sh` is the only caller.

Vendored from [ai-on-gke/tools](https://github.com/ai-on-gke/tools) at
`462a06c810c00868514edadf8adfd149ea1d6943` (2026-07-22), Apache 2.0, © Google LLC.

## Why a fork and not a fetch

It used to be fetched at that commit on every build. Two things make owning it the
smaller cost:

- **Upstream stopped.** `462a06c` is the tip of `main`, not a pin behind it. There
  is nothing to bump to, so a bug there is ours to fix either way.
- **It rots on its own.** The builder boots a Debian VM to do the unpacking, and
  upstream hardcoded `debian-11-bullseye-v20230912`. Three years on, that image is
  deprecated and bullseye's apt index still resolves while the pool file it names
  is gone, so `apt install containerd` returns 404 and the startup script exits
  before pulling anything. Patching a fetched tree with `sed` would have worked
  until upstream touched the line.

It cannot be an ordinary Go dependency: its `go.mod` declared the
`GoogleCloudPlatform/ai-on-gke` path, and that directory was deleted from that
repo, so `go get` reaches only an abandoned 2023 snapshot.

## Changes from upstream

- `imager.go`: the builder's boot image is now the `debian-12` **family** rather
  than a dated image, via a `builderSourceImage` const. A family tracks its newest
  member, so this cannot break the same way again. Bookworm and not trixie because
  `script/startup.sh` was written against bullseye, and bookworm's containerd 1.6
  keeps the `ctr -n k8s.io snapshot view` behaviour it relies on.
- No `go.mod`: it is a package of this repo's root module, so its
  dependencies are pinned in the root `go.mod`.
- `gofmt`'d. Upstream's tree was not, and this repo's formatter covers every
  `.go` file outside `./vendor/` and `./third_party/`.

`make -C toolchain/preload-disks/ci-cache test` runs the upstream tests in the
golang image.

## Re-syncing

If upstream ever moves, diff against it rather than copying over the top — the
changes above have to survive:

```sh
git clone --depth 1 https://github.com/ai-on-gke/tools /tmp/aiongke
diff -ru /tmp/aiongke/gke-disk-image-builder . \
  | grep -v '^Only in \.' | less
```
