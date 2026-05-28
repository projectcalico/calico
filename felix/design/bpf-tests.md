<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# eBPF dataplane — Tests

How the BPF dataplane is exercised: the `bpf/ut/` harness and the
packet-traversal scenarios it composes, the BPF FV matrix-prefix
convention and the `_BPF-SAFE_` boundary between BPF-specific and
dataplane-agnostic FV tests, and the test-level invariants every
BPF change must hold.

This is one of several sub-designs for the eBPF dataplane. See
[`bpf-overview.md`](./bpf-overview.md) for the packet-path mental
model, the fast-path cost rule, and the cross-cutting review notes
that apply to every BPF change. Felix-wide test discipline (when a
PR must include a test, how to choose the level) lives in
[`.claude/CLAUDE.md` → Tests required for code changes](../../.claude/CLAUDE.md).
The full set of sub-designs is listed in
[`felix/DESIGN.md`](../DESIGN.md).

## BPF unit test harness (`bpf/ut/`)

`bpf/ut/bpf_prog_test.go` is the test harness. Each file in
`bpf/ut/` covers one feature area — NAT, ICMP, policy, BPF load
verification, encapsulation, and so on. Each Go test function
describes a **scenario** (the maps, routes, conntrack entries,
attach-point globals) and runs a series of **sub-tests** against
that scenario.

Each sub-test exercises a single BPF program attached to a single
interface in a single direction. The scenario is set up *outside*
the sub-test so that back-to-back sub-tests can build a multi-step
narrative.

The narrative is a **packet traversal**: each sub-test feeds the
previous sub-test's output into the next program in the chain.
For example, a from-pod sub-test runs the workload-egress program
(TC ingress on a `cali*` veth) through policy, NAT, and conntrack
creation; the next sub-test takes the resulting packet and runs
it through the host-egress program on a tunnel or main interface;
a return packet runs the chain in reverse.

Assigning to `hostIP` between sub-tests simulates a hop to another
node — host-to-host traversal within the cluster.

Reading a test in this style is reading a packet's life. Adding a
test means picking a feature, choosing the scenario, and writing
the sub-tests in packet-flow order with the scenario shared across
the chain.

### Verifier coverage: `TestPrecompiledBinariesAreLoadable`

`TestPrecompiledBinariesAreLoadable` loads every compiled BPF
program through the kernel verifier on the test host. Because BPF
sources compile to many variants — IPv4, IPv6, TC ingress, TC
egress, XDP, fast-path, debug-path, plus per-`AttachType`
differences — a change can pass `make build-bpf` (compilation)
and still fail the verifier on a variant the developer didn't
exercise. This test is the verifier gate every BPF PR has to pass.

### Review notes for this section

- A bug in BPF C is testable in the harness: the program is
  loaded, packets are crafted, output is asserted. A fix without
  a UT-level reproducer is a red flag — the harness reaches the
  bug if the bug exists.
- A new sub-test must follow the packet-flow ordering convention.
  Out-of-order sub-tests in a shared scenario are surprising for
  reviewers and break when the scenario is reused.
- A change to BPF C that doesn't run
  `TestPrecompiledBinariesAreLoadable` locally is reviewer-gating:
  ask for the verifier output before approving.

## BPF FV (`fv/bpf_*_test.go`) and the matrix prefix

BPF functional tests live alongside the rest of Felix FV in
`felix/fv/`. There are two categories:

- **`fv/bpf_*_test.go`** — tests focused on the BPF dataplane
  itself. They run only with the BPF dataplane enabled and
  exercise BPF-specific behaviour (verifier-loaded programs, BPF
  conntrack interactions, BPF NAT, attach-point lifecycle).
- **`_BPF-SAFE_`-prefixed tests in other FV files** — tests that
  exercise Calico's general behaviour (policy enforcement,
  network-policy semantics) and are largely the same regardless
  of dataplane. The prefix marks them as runnable under BPF mode.

A test in `fv/bpf_*_test.go` carries a **matrix prefix**
identifying the dataplane parameter combination it represents:

```
"ipv4 udp, ct=true, log=debug, tunnel=none, dsr=false"
```

| Parameter   | Values                                                   |
|-------------|----------------------------------------------------------|
| ip version  | `ipv4`, `ipv6`                                           |
| protocol    | `tcp`, `udp`, `udp-unconnected`, `udp-conn-recvmsg`      |
| ct          | `true`, `false`                                          |
| log         | `debug`, `off`                                           |
| tunnel      | `none`, `ipip`, `vxlan`, `wireguard`                     |
| dsr         | `true`, `false`                                          |

The matrix expands one test specification across many parameter
combinations and lets `GINKGO_FOCUS` regex-match a slice of the
matrix when triaging a failure (e.g.
`GINKGO_FOCUS="ipv4 udp, ct=true, log=debug, tunnel=none, dsr=false.*MyTest"`).

### Review notes for this section

- A behaviour that varies along an existing matrix axis must be
  exercised across the relevant axis values, not just the
  developer's local combination.
- A behaviour that needs a *new* axis means extending the matrix
  in `fv/bpf_*_test.go` and the surrounding fixture so the new
  axis is exercised. The matrix is itself a design surface — a
  feature that doesn't fit it usually means either the feature
  or the matrix needs reshaping.
- A fix or feature that is reachable in `bpf/ut/` should land its
  primary coverage there, not in FV. FV is for behaviour that
  depends on real interfaces, real conntrack interaction, or
  real packet flow through the host stack — see
  [`.claude/CLAUDE.md` → Tests required for code changes](../../.claude/CLAUDE.md).

## Cross-cutting test invariants

- A BPF C source change must compile to every variant the file
  produces. `make build-bpf` walks every variant; a change that
  compiles in one variant and breaks another regresses CI.
- A BPF C source change must pass
  `TestPrecompiledBinariesAreLoadable`. The kernel verifier sees
  variants compilation alone does not.
- A new sub-program, mark bit, CT flag, or map field arrives with
  UT coverage in the matching `bpf/ut/` file
  (`nat_*_test.go`, `policy_*_test.go`, etc.). Tests-only
  follow-ups are an anti-pattern: by the time they land, the
  feature has shipped untested.

---

## Keep this doc in sync with the code

A change to how the BPF dataplane is tested in the area this file
covers must update the relevant section in the same PR — new
harness pattern, new matrix axis, new UT category, new
verifier-time gate. Exemptions: (a) bug fix restoring documented
behaviour, (b) mechanical refactor with no observable change,
(c) comment / log-message edits, (d) dependency bumps. If in
doubt, update.

Cross-cutting rules that apply to **every** BPF change (map
versioning, mark discipline, sub-program registration, kernel-
version sensitivity) live in
[`bpf-overview.md` → Cross-cutting review notes](./bpf-overview.md).
Felix-wide test discipline lives in
[`.claude/CLAUDE.md` → Tests required for code changes](../../.claude/CLAUDE.md).
