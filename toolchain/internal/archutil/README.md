# archutil (vendored)

Detects which architectures the kernel can run through binfmt_misc. Only
`toolchain/cmd/binfmt` uses it.

Copied from [moby/buildkit](https://github.com/moby/buildkit) `util/archutil`
at v0.32.2 (`991535e0973488b6a429096d21fa13f81f2d89d8`), Apache 2.0. The generated per-arch test binaries are
unchanged; their sources and generator stay upstream.

## Why a copy and not the module

binfmt uses this one package. Requiring all of buildkit from the root module
raises shared dependencies the product builds with: `Microsoft/hcsshim` to a
v0.15 pre-release, plus `go-winio`, the AWS SDK and `golang.org/x/exp`.

## Local change

`detect.go` logs through logrus instead of buildkit's `util/bklog`, which
would bring the rest of buildkit back.
