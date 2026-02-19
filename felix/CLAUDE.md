# Felix Development Guide

## Running Tests

### BPF Unit Tests

```bash
make FOCUS="TestName" ut-bpf
```

Runs BPF unit tests from `bpf/ut/`. `FOCUS` filters by test name.

### BPF Functional Tests

```bash
make fv-bpf GINKGO_FOCUS="TestName"
```

Runs BPF functional tests from `fv/*_test.go`. Only tests prefixed with `_BPF-SAFE_` are included. `GINKGO_FOCUS` filters by test name (supports regex).

BPF FV tests can be further refined with a prefix that specifies the test matrix parameters:

```
"ipv4 udp, ct=true, log=debug, tunnel=none, dsr=false"
```

Prefix format: `<ip-version> <protocol>, ct=<bool>, log=<level>, tunnel=<mode>, dsr=<bool>`

| Parameter | Values                                      |
|-----------|---------------------------------------------|
| ip version| `ipv4`, `ipv6`                              |
| protocol  | `tcp`, `udp`, `udp-connected`               |
| ct        | `true`, `false`                              |
| log       | `debug`, `none`                              |
| tunnel    | `none`, `ipip`, `vxlan`, `wireguard`         |
| dsr       | `true`, `false`                              |

Example: run a specific BPF FV test only for IPv4 UDP with no tunnel:

```bash
make fv-bpf GINKGO_FOCUS="ipv4 udp, ct=true, log=debug, tunnel=none, dsr=false.*MyTestName"
```

## BPF Code Structure

### C Source Code (`bpf-gpl/`)

GPL-licensed BPF programs compiled to eBPF bytecode with clang/LLVM.

#### Entry Point Programs

| File | Purpose |
|------|---------|
| `tc.c` | Main TC (Traffic Control) hook — processes ingress/egress traffic |
| `xdp.c` | XDP hook — early packet processing at NIC driver level |
| `connect_balancer.c` | IPv4 cgroup connect-time load balancer |
| `connect_balancer_v6.c` | IPv6 cgroup connect-time load balancer |
| `connect_balancer_v46.c` | Dual-stack balancer variant |
| `conntrack_cleanup.c` | Connection tracking garbage collection |
| `policy_default.c` | Default policy fallback rules |
| `tc_preamble.c` / `xdp_preamble.c` | Hook initialization/setup |

#### Key Headers (`bpf-gpl/*.h`)

- **Infrastructure**: `bpf.h`, `types.h`, `globals.h` — core definitions, compile flags, global state maps
- **Parsing**: `parsing.h`, `parsing4.h`, `parsing6.h`, `skb.h` — packet parsing helpers
- **NAT**: `nat.h`, `nat4.h`, `nat6.h`, `nat_types.h`, `nat_lookup.h`
- **Conntrack**: `conntrack.h`, `conntrack_types.h` — connection tracking state
- **Policy**: `policy.h`, `failsafe.h` — policy evaluation, failsafe rules
- **Routing**: `routes.h`, `fib.h`, `fib_common.h`, `fib_co_re.h`, `fib_legacy.h`
- **Protocol**: `tcp4.h`, `tcp6.h`, `icmp.h`, `icmp4.h`, `icmp6.h`, `arp.h`
- **Load Balancing**: `jenkins_hash.h`, `maglev.h`, `ctlb.h`
- **Utilities**: `jump.h` (tail calls), `log.h`, `events.h`, `counters.h`

Dual-stack support uses separate IPv4/IPv6 header variants and `#ifdef IPVER6` for conditional compilation. Compile flags (`CALI_COMPILE_FLAGS`) control which code paths are active.

#### Subdirectories

- `bpf-gpl/bin/` — compiled eBPF `.o` object files
- `bpf-gpl/libbpf/` — libbpf dependency (kernel headers, BPF helpers)
- `bpf-gpl/ut/` — C-level unit test programs (ICMP, parsing, NAT, perf)
- `bpf-gpl/libbpf/include/uapi/` — kernel UAPI headers used by BPF programs

### Go User-Space Code (`bpf/`)

Go packages that manage BPF programs and maps from user space.

| Package | Purpose |
|---------|---------|
| `bpf/*.go` | Main interface — program management, attach/detach, syscalls |
| `conntrack/` | Conntrack map versioning (v2–v4), cleanup, scanner |
| `nat/` | NAT map management |
| `polprog/` | Policy program code generation |
| `ipsets/` | IP set map construction |
| `maps/` | Generic BPF map operations |
| `routes/` | Route/FIB lookups |
| `hook/` | Hook attachment (TC, XDP, cgroup) |
| `tc/`, `xdp/` | TC/XDP specific logic |
| `jump/` | Tail call jump management |
| `counters/`, `events/`, `perf/` | Stats, events, perf ringbuffers |
| `failsafes/`, `filter/`, `arp/` | Failsafe rules, filtering, ARP |
| `proxy/` | Kube-proxy replacement — implements service load balancing in BPF |
| `ut/` | BPF unit tests (Go test harness) |

### BPF Dataplane Management (`dataplane/linux/`)

`dataplane/linux/bpf_*.go` — manages the BPF dataplane from user space (program lifecycle, map syncing, endpoint management).
