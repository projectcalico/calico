# Felix Development Guide

## Architecture Overview

Felix is the per-node agent in Calico that enforces network policy and programs routing. The data pipeline flows:

**Datastore syncer** → **AsyncCalcGraph** → **CalcGraph** (dispatcher + calculation nodes) → **EventSequencer** → **InternalDataplane** (managers) → **dataplane operations**

1. Datastore updates (Kubernetes, etcd) arrive via a syncer
2. `CalcGraph` processes them through a graph of calculation nodes (policy resolution, route resolution, IP set indexing, etc.)
3. `EventSequencer` buffers and coalesces the outputs, flushing in dependency-safe order
4. The dataplane driver fans updates to managers, each owning a slice of dataplane state

Felix supports multiple dataplane backends: **BPF**, **iptables**, **nftables**, and **Windows** (HNS/HCN).

Key files: `daemon/daemon.go`, `calc/calc_graph.go`, `dataplane/linux/int_dataplane.go`, `dataplane/driver.go`

## Calc Graph Engine (`calc/`)

The calc graph is an event-processing pipeline that transforms raw datastore updates into dataplane-ready instructions.

### Key Components

- **`AllUpdDispatcher`** (`*dispatcher.Dispatcher` field on `CalcGraph`) — fans out datastore updates by resource type to downstream nodes
- **`ActiveRulesCalculator`** — tracks which policies/profiles are active based on endpoint labels
- **`RuleScanner`** — scans rules for selector references, feeds the IP set index
- **`PolicyResolver`** — resolves per-endpoint policy ordering (tiers, priorities)
- **`L3RouteResolver`** — computes routes from IP pools, workload endpoints, and host IPs
- **`VXLANResolver`** — computes VTEP (VXLAN tunnel endpoint) entries
- **`EncapsulationResolver`** — determines encapsulation mode from IP pool config

### PipelineCallbacks

`PipelineCallbacks` is a composite interface (`calc/calc_graph.go`) assembling all callback types the calc graph emits: IP sets, active rules, routes, endpoints, config, encapsulation, VTEPs, wireguard keys, and service updates. `EventSequencer` is the primary implementation.

### EventSequencer

`EventSequencer` (`calc/event_sequencer.go`) buffers updates in `pending*` maps/sets and flushes them via `Flush()` in dependency-safe order (e.g., IP sets before policies that reference them). It coalesces rapid updates so only the final state is sent downstream.

Key files: `calc/calc_graph.go`, `calc/event_sequencer.go`, `calc/active_rules_calculator.go`, `calc/l3_route_resolver.go`

## Dataplane Manager Pattern (`dataplane/linux/`)

### Manager Interface

All dataplane managers implement:

```go
type Manager interface {
    OnUpdate(protoBufMsg any)
    CompleteDeferredWork() error
}
```

Extended interfaces: `ManagerWithRouteTables` (exposes route table syncers), `ManagerWithRouteRules` (exposes routing rules), `UpdateBatchResolver` (pre-apply batch resolution).

### Event Loop

`InternalDataplane` (`int_dataplane.go`) runs the main loop:

1. Receive messages from the calc graph
2. Fan out via `OnUpdate()` to all registered managers
3. Throttled `apply()` cycle: call `CompleteDeferredWork()` on each manager, then sync route tables and rules

### Managers

Managers are registered via `RegisterManager()`. Key managers include:

| Manager | Handles |
|---------|---------|
| `endpointManager` / `bpfEndpointManager` | Workload/host endpoint programming |
| `policyManager` / `rawEgressPolicyManager` | Policy chain/rule generation |
| `ipsetsManager` | IP set synchronization |
| `noEncapManager` / `vxlanManager` | Route management for encap modes |
| `ipipManager` | IPIP tunnel interfaces |
| `wireguardManager` | WireGuard tunnel setup |
| `masqManager` | IP masquerade rules |
| `hostIPManager` | Host IP tracking |
| `floatingIPManager` | Floating IP NAT |
| `dscpManager` | DSCP marking |
| `serviceLoopManager` | Service loop prevention |
| `failsafeMgr` | BPF failsafe port programming |

IPv4 and IPv6 each get their own manager instances. `dataplane/driver.go` is the factory that constructs and wires the dataplane.

Key file: `dataplane/linux/int_dataplane.go`

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

## BPF Dataplane

### BPF Code Structure

#### C Source Code (`bpf-gpl/`)

GPL-licensed BPF programs compiled to eBPF bytecode with clang/LLVM.

##### Entry Point Programs

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

##### Key Headers (`bpf-gpl/*.h`)

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

##### Subdirectories

- `bpf-gpl/bin/` — compiled eBPF `.o` object files
- `bpf-gpl/libbpf/` — libbpf dependency (kernel headers, BPF helpers)
- `bpf-gpl/ut/` — C-level unit test programs (ICMP, parsing, NAT, perf)

#### Go User-Space Code (`bpf/`)

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

#### BPF Unit Test Pattern (`bpf/ut/`)

`bpf/ut/bpf_prog_test.go` is the test harness. Each file in `bpf/ut/` presents a set of tests for one feature (NAT, ICMP handling, policy, BPF load verification, etc.). Each test has sub-tests that exercise a BPF program attached to a single interface in a single direction (ingress or egress) in a single scenario. The scenario (maps, routes, conntrack entries, etc.) is set up outside the sub-test.

Typically, back-to-back sub-tests simulate a packet traversing from one interface to the next — for example, host to workload or workload to workload on the same host. Assigning to `hostIP` and running host-to-host back-to-back sub-tests simulates a packet traversing from one host to another within the cluster.

#### BPF Dataplane Management (`dataplane/linux/`)

`dataplane/linux/bpf_*.go` — manages the BPF dataplane from user space (program lifecycle, map syncing, endpoint management).

## Iptables/Nftables Dataplane

The netfilter-based policy engine uses a layered architecture:

### generictables/

Abstract table interface (`table.go`, `actions.go`, `match_builder.go`, `rules.go`) shared by both iptables and nftables backends. Defines `Table`, `Chain`, `Rule`, `Action`, and `MatchCriteria` types.

### iptables/

Legacy netfilter backend: `table.go` (table sync via `iptables-restore`), `actions.go`, `match_builder.go`, `renderer.go` (renders rules to iptables syntax).

### nftables/

Modern netfilter backend: `table.go` (table sync via nftables API), `ipsets.go`, `maps.go`, `match_builder.go`.

### rules/

Shared rule generation logic used by both backends:

- `dispatch.go` — per-endpoint dispatch chains
- `policy.go` — policy chain generation from Calico policy model
- `endpoints.go` — endpoint-specific chain setup
- `static.go` — static/boilerplate chains (filter, NAT, mangle)
- `nat.go` — NAT rule generation

### Backend Selection

Controlled by `NFTablesMode` config parameter. Both backends implement the `generictables` interface, allowing the dataplane to switch between them. Key managers: `endpoint_mgr.go`, `policy_mgr.go` in `dataplane/linux/`.

## Windows Dataplane (`dataplane/windows/`)

HNS/HCN-based policy engine for Windows nodes.

- `win_dataplane.go` — main dataplane driver (analogous to `int_dataplane.go` on Linux)
- `endpoint_mgr.go` — Windows endpoint management
- `policy_mgr.go` — Windows policy sets
- `vxlan_mgr.go` — VXLAN overlay on Windows

Subdirectories: `hns/` (Host Networking Service), `hcn/` (Host Compute Network), `ipsets/`, `policysets/`

## Networking and Routing

Shared networking subsystems used across dataplanes:

| Package | Purpose |
|---------|---------|
| `routetable/` | Linux route table management via netlink (`route_table.go`) |
| `routerule/` | Policy-based routing rules |
| `vxlanfdb/` | VXLAN forwarding database management |
| `wireguard/` | WireGuard tunnel setup and key management |
| `ifacemonitor/` | Interface state monitoring (link up/down, address changes) |
| `nfnetlink/` | Conntrack and nflog via netfilter netlink |
| `netlinkshim/` | Netlink abstraction layer for testing and portability |

## Configuration

- `config/config_params.go` — all Felix parameters with defaults and metadata
- `config/param_types.go` — parameter type definitions, parsing, and validation
- Configuration is loaded from environment variables, config files, and the Calico datastore (in that priority order)
