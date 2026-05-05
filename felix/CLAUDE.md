# Felix Operational Guide

This file is **operational guidance** for agents working in Felix: how to build, run tests, debug, and use Felix-specific tooling.

For **architecture, invariants, and review criteria**, see [`felix/DESIGN.md`](./DESIGN.md) — the design index — and the per-topic sub-designs under [`felix/design/`](./design/). Do not look here for invariants; look there.

## Running Tests

### Unit Tests

```bash
make ut
```

Runs all Go unit tests (via Ginkgo with coverage). Skips `fv/`, `k8sfv/`, and `bpf/ut/` packages. Pass `GINKGO_ARGS` for extra flags (e.g., `GINKGO_ARGS="-focus=TestName"`).

### Functional Tests

```bash
make fv GINKGO_FOCUS="TestName"
```

Runs functional tests from `fv/`. Requires container images to be built first. `GINKGO_FOCUS` filters by test name (supports regex). Can be parallelized with `FV_NUM_BATCHES` and `FV_BATCHES_TO_RUN`.

### BPF-Specific Tests

#### Building BPF Programs

After modifying C code in `bpf-gpl/`, verify it compiles for all targets (IPv4, IPv6, all hook types):

```bash
make build-bpf
```

Run `make clean` first if you hit stale object issues. Use `make -C felix build` to verify both BPF C and Go code compile together.

#### BPF Unit Tests

BPF unit tests run the BPF dataplane programs in a privileged container:

```bash
make ut-bpf                          # Run all BPF unit tests (~2000 tests)
make FOCUS="TestName" ut-bpf         # Run specific test by name
make FOCUS="TestNatEncap" ut-bpf     # Example: VXLAN encap/decap tests
make FOCUS="TestNATPodPodXNode" ut-bpf  # Example: cross-node NAT tests
```

`FOCUS` filters by Go test function name (supports regex). Each test function typically has multiple sub-tests exercising different BPF programs (ingress/egress, different interface types).

`TestPrecompiledBinariesAreLoadable` verifies that all compiled BPF programs pass the kernel verifier on the local machine. Always run this after modifying BPF C code to catch verifier rejections early:

```bash
make FOCUS="TestPrecompiledBinariesAreLoadable" ut-bpf
```

BPF functional tests run the standard FV suite with the BPF dataplane enabled:

```bash
make fv-bpf GINKGO_FOCUS="TestName"
```

Tests in `fv/bpf_*_test.go` are focused on the BPF dataplane itself. Tests prefixed with `_BPF-SAFE_` in other FV files test Calico's general behavior and are largely the same across all dataplanes. The dataplane tests in `fv/bpf_*_test.go` can be refined with a matrix prefix:

```
"ipv4 udp, ct=true, log=debug, tunnel=none, dsr=false"
```

| Parameter | Values                                      |
|-----------|---------------------------------------------|
| ip version| `ipv4`, `ipv6`                              |
| protocol  | `tcp`, `udp`, `udp-unconnected`, `udp-conn-recvmsg` |
| ct        | `true`, `false`                              |
| log       | `debug`, `off`                               |
| tunnel    | `none`, `ipip`, `vxlan`, `wireguard`         |
| dsr       | `true`, `false`                              |

Example: run a specific BPF FV test only for IPv4 UDP with no tunnel:

```bash
make fv-bpf GINKGO_FOCUS="ipv4 udp, ct=true, log=debug, tunnel=none, dsr=false.*MyTestName"
```

### Nftables Functional Tests

```bash
make fv-nft GINKGO_FOCUS="TestName"
```

Runs FV tests with the nftables backend enabled (`FELIX_FV_NFTABLES=Enabled`).

### Diagnosing Test Failures with fv-tests-guru

[fv-tests-guru](https://github.com/tigera/fv-tests-guru) is an AI-powered tool that parses Felix FV/UT failure logs and runs AI analysis to diagnose root causes. It reads its Gemini API key from `~/.fv-tests-guru/gemini-key`.

**When asked to analyze a test failure log file, always run fv-tests-guru FIRST** (if available — check with `which fv-tests-guru`) — it is the most efficient way to identify the failing test(s), extract relevant context, and get an initial diagnosis. Use its output to guide subsequent investigation (reading test code, checking source changes, etc.). If fv-tests-guru is not installed, skip it and proceed with manual analysis.

```bash
fv-tests-guru -debug-logfile <log-path> -ai-provider gemini -calico-repo <path-to-calico-repo-root> -max-timeout 1m40s
```

Add `-ut` for unit test logs. Use `-extra-context "..."` to provide hints about the branch under test.

## BPF unit test harness (`bpf/ut/`)

`bpf/ut/bpf_prog_test.go` is the test harness. Each file in `bpf/ut/` presents a set of tests for one feature (NAT, ICMP handling, policy, BPF load verification, etc.). Each test has sub-tests that exercise a BPF program attached to a single interface in a single direction (ingress or egress) in a single scenario. The scenario (maps, routes, conntrack entries, etc.) is set up outside the sub-test.

Typically, back-to-back sub-tests simulate a packet traversing from one interface to the next — for example, host to workload or workload to workload on the same host. Assigning to `hostIP` and running host-to-host back-to-back sub-tests simulates a packet traversing from one host to another within the cluster.

## Configuration parameters

Felix parameters are declared in `config/config_params.go` with types and validation in `config/param_types.go`. When adding a new parameter, both files are updated; the docs under `felix/docs/config-params.md` are regenerated by `make generate`.

## Design and review criteria

Architecture, invariants, and review criteria live in the design index [`felix/DESIGN.md`](./DESIGN.md) and the per-topic sub-designs under [`felix/design/`](./design/). Path-scoped Copilot rules that reference each sub-design live under [`.github/instructions/`](../.github/instructions/). Do not look here for dataplane invariants, calc-graph internals, or rule-generation rules — look in the matching sub-design.
