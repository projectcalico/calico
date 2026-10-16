# archutil (vendored)

Detects which architectures the kernel can run, by executing a tiny static test
binary for each. `toolchain/cmd/binfmt` uses it so `--install all` registers
QEMU only for architectures the host cannot already run. Registering an
emulator for the native one would take over the host's own binaries.

Copied from [moby/buildkit](https://github.com/moby/buildkit) `util/archutil`
at v0.32.2 (`991535e0973488b6a429096d21fa13f81f2d89d8`), Apache 2.0. The
generated test binaries are unchanged; their sources and generator stay
upstream.

## Why a copy and not the module

binfmt uses this one package. Requiring all of buildkit from the root module
raises shared dependencies the product builds with: `Microsoft/hcsshim` to a
v0.15 pre-release, plus `go-winio`, the AWS SDK and `golang.org/x/exp`.

## Local changes

Only amd64, arm64, ppc64le and s390x remain, the architectures calico/binfmt
ships QEMU for. The other architectures' files are not copied.

`detect.go` keeps upstream's lines, with the parts that need them commented
out, so an upstream change still applies to it. `WarnIfUnsupported` is
commented out too: nothing here calls it, and it needs buildkit's logger.
