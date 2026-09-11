# BPF C Programs (`felix/bpf-gpl`)

Operational guidance for the eBPF dataplane programs. For the design of the
programs themselves see [`felix/DESIGN.md`](../DESIGN.md) and the `bpf-*.md`
sub-designs under [`felix/design/`](../design/).

## Layout and licensing

- `bpf-gpl/` — the dataplane programs. Dual licensed GPL v2.0/Apache for Linux
  kernel compatibility; every file carries the `Apache-2.0 OR GPL-2.0-or-later`
  SPDX header. Nothing enforces this automatically — add it yourself.
- `bpf-apache/` — Apache-only BPF code.
- `ut/` — C entry points for the BPF unit tests in `felix/bpf/ut`.
- Tooling versions (`LIBBPF_VERSION`, `BPFTOOL_IMAGE`) are pinned in
  [`metadata.mk`](../../metadata.mk). Run `make -C felix clone-libbpf` before
  your first build.

## Building and checking

All commands run from `felix/`, in the go-build container:

```bash
make build-bpf                                          # every variant: IPv4/IPv6, all hook types
make check-bpf-headers                                  # include guards + header self-containment (~5s)
make FOCUS="TestPrecompiledBinariesAreLoadable" ut-bpf  # every object passes the local kernel's verifier
```

Run `make clean` first if you hit stale object issues. `make build` compiles
BPF C and Go together. The BPF unit and FV test invocations are in
[`felix/CLAUDE.md`](../CLAUDE.md).

`check-bpf-headers` runs from `make static-checks`, so CI fails on a header
that is not self-contained.

## Headers and includes

`./check-headers` enforces the first two rules; follow the rest by hand.

- **Every header is self-contained.** Include what you use, so that include
  order never matters and no header relies on its includer.
- **Guard every header** with `#ifndef __CALI_<FILENAME>_H__` /
  `#define __CALI_<FILENAME>_H__` (e.g. `nat_types.h` → `__CALI_NAT_TYPES_H__`).
  The name is derived from the file name so guards are unique by construction.
- **Order includes** as system headers (`<linux/...>`, `<std...>`), a blank
  line, then project headers, each group sorted alphabetically. Where a header
  picks its IPv4 or IPv6 twin, that `#ifdef IPVER6` block comes last:

  ```c
  #include <linux/if_ether.h>
  #include <linux/in.h>

  #include "bpf.h"
  #include "log.h"
  #include "nat_types.h"
  #ifdef IPVER6
  #include "nat6.h"
  #else
  #include "nat4.h"
  #endif
  ```

- **`.c` files define `CALI_LOG` before any include.** `log.h` only defines
  it when unset, so the override must come first.
- **`bpf.h` is the root of the include graph.** Only `bpf_inline.h`,
  `globals.h` and `ip_addr.h` sit below it: userspace (`felix/bpf/libbpf`)
  includes them via cgo, so they must not pull in `bpf.h` or the BPF helpers.
  `check-headers` compiles them with the host compiler to keep that true.
- **A header that defines a map must be listed in `IP_MAP_HEADERS`,
  `COMMON_MAP_HEADERS` or `XDP_MAP_HEADERS` in the `Makefile`.** Felix creates
  maps by looking them up by name in the generated map-stub objects; a map
  missing from the stubs loses its BTF.
- `check-headers` has a table of which build variants each header is meant for
  (`only`); a header that is XDP-only, cgroup-only or IPv4/IPv6-only needs an
  entry there.
