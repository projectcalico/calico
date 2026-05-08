// docker-bake.hcl - buildx bake config for non-Go Calico images.
//
// This is the entry point for buildx-based image builds. It currently covers
// calico/node, where the multi-stage Dockerfile has expensive layers (BIRD,
// runit, iptables, conntrack package install) that benefit from BuildKit's
// content-addressed layer cache and registry-backed cache sharing across
// fresh CI runners.
//
// Pure-Go images (e.g. calico/calico) are built with ko, not bake — see
// PR #12710. ko handles single-binary images more cleanly than a multi-
// stage Dockerfile.
//
// Usage:
//   docker buildx bake calico-node
//   docker buildx bake calico-node \
//     --set calico-node.cache-from=type=registry,ref=<registry>/calico/node-buildcache \
//     --set calico-node.cache-to=type=registry,ref=<registry>/calico/node-buildcache,mode=max
//
// The calico and mountns binaries are pre-built outside this target by the
// existing Make path and copied in via BIN_DIR. Bake covers the image-
// assembly side; BUILD_CACHE (the existing GCS-backed .go-pkg-cache restore
// in CI) covers the Go-build side. The two stack.

variable "UBI_IMAGE"     { default = "registry.access.redhat.com/ubi9/ubi-minimal:latest" }
variable "BIRD_VERSION"  { default = "v0.3.3-211-g9111ec3c" }
variable "BIRD_IMAGE"    { default = "calico/bird:${BIRD_VERSION}-amd64" }
variable "BPFTOOL_IMAGE" { default = "calico/bpftool:v7.5.0" }
variable "GIT_VERSION"   { default = "dev" }

group "default" {
  targets = ["calico-node"]
}

target "calico-node" {
  context    = "node"
  dockerfile = "Dockerfile"
  args = {
    BIRD_IMAGE    = BIRD_IMAGE
    BPFTOOL_IMAGE = BPFTOOL_IMAGE
    UBI_IMAGE     = UBI_IMAGE
    BIN_DIR       = "dist/bin"
    GIT_VERSION   = GIT_VERSION
  }
  platforms = ["linux/amd64"]
  tags      = ["calico/node:bake-amd64"]
  output    = ["type=docker"]
}
