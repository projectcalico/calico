# BPF FV Tests

The BPF functional verification tests were originally in a single `bpf_test.go`
file (~6500 lines). They have been refactored into smaller, focused files for
better navigability and maintainability.

## Architecture

A `bpfTestContext` struct (defined in `bpf_test.go`) holds all shared test state
(infrastructure, workloads, clients, options, etc.) and is passed to each
extracted test function. This replaces the closure variables that previously
tied all test sections together in a single function.

## File Overview

| File | Lines | Description |
|------|-------|-------------|
| `bpf_test.go` | ~1330 | Entry point: test options, `bpfTestContext` struct and methods, `describeBPFTests` skeleton with BeforeEach/AfterEach setup, base multi-node connectivity tests, DNAT test, and calls to extracted test functions |
| `bpf_helpers_test.go` | ~850 | Standalone helper functions: NAT/backend/conntrack/route map dumpers, BPF program verification, K8s service and endpoint helpers, policy helpers, conntrack flush/check utilities |
| `bpf_single_node_test.go` | ~830 | Single-node tests: `DefaultEndpointToHostAction` variants (DROP/ACCEPT), `IptablesMarkMask`, workload-to-host connectivity, policy enforcement, BPF program cleanup and recovery, Felix readiness checks |
| `bpf_service_test.go` | ~1690 | Service load-balancing tests: ClusterIP, ExternalIP, LoadBalancer, source IP preservation, Maglev hashing, session affinity, service creation/deletion transitions, endpoint slice handling |
| `bpf_nodeport_test.go` | ~1460 | NodePort tests: NodePort connectivity from various sources, forward traffic between nodes, MTU handling, ICMP needs-frag, ARP behavior, host-networked pod services |
| `bpf_special_test.go` | ~590 | Special configuration tests: BPF enablement/disablement, third-party CNI mode, host interface attachment, RPF (reverse path filtering) strict mode enforcement |

## Test Matrix

Each test file's functions are called multiple times from `bpf_test.go` with
different combinations of:

- **Protocol**: TCP, UDP, UDP-unconnected
- **IP family**: IPv4, IPv6
- **Connection-time load balancing**: enabled/disabled
- **Tunnel mode**: none, IPIP, VXLAN, WireGuard
- **DSR (Direct Server Return)**: enabled/disabled
- **BPF log level**: debug, off

## Running Tests

```bash
# Run all BPF FV tests
make fv-bpf

# Run a specific test by name (use dots for spaces in regex)
make fv-bpf GINKGO_FOCUS="no.connectivity.to.a.pod"
```
