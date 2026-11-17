# BIRD

This directory builds the `calico/bird` image. The image does two jobs:

- It carries **BIRD** 1.6.8 rebuilt as an RPM, with the patches in `patches/`. The calico/node image build installs that RPM. BIRD is under the GNU GPL, version 2 or later.
- It runs as a BGP router. It has the RPM installed, a base config from `router/`, and an entrypoint that starts `bird` and `bird6`. A test runs the image, drops its peer config into `/etc/bird/` or `/etc/bird6/`, and runs `birdcl configure`.

BIRD 1.6.8 is the last release of the BIRD 1.6 line. The patches are the changes that the [projectcalico/bird](https://github.com/projectcalico/bird) fork carried on top of it. Each patch file records the fork commits it was squashed from, with their authors and messages.

## Versions

The RPM is `bird-1.6.8-N.tigera`, and BIRD reports `1.6.8-N.tigera` as its version. `N` is `calico_release` in `bird.spec`. Raise it whenever a patch is added, removed or changed.

The image tag is a hash of this directory's build inputs, so it changes with any of them. `CalicoBIRD` in `e2e/pkg/utils/images/images.go` names the tag, and a test there fails until it is updated.

## Source availability

The package is built entirely from the pinned upstream release tarball plus the spec file and patches in this directory. Together they are the complete corresponding source. The tarball's version and SHA are in `metadata.mk` at the repo root.

The image holds all three under `/src`. calico/node copies that into `/included-source`, so the source for the GPL binaries ships in the image alongside them.
