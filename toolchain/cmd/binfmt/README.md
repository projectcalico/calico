# binfmt (vendored)

Registers QEMU interpreters with the kernel's binfmt_misc. It is the entrypoint
of calico/binfmt.

From [tonistiigi/binfmt](https://github.com/tonistiigi/binfmt) `cmd/binfmt` at
`e41434fefad6aee7b01fbe5efc1c4b6f6c735fff`, MIT. `version.go` matches upstream. `config.go` lists the
architectures calico/binfmt ships, and `main.go` imports the vendored
`toolchain/internal/archutil` rather than buildkit's.
