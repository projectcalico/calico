# Calico threat model

Calico provides container networking and network policy for Kubernetes. Its core promise is that traffic flows only where policy allows. Policy is written partly by cluster admins and partly by namespace users, and is enforced on every node against traffic from workloads we do not trust. Findings that break that promise matter most to us.

Architecture: `DESIGN.md` at the repository root, the per-component `DESIGN.md` files it links to, and `felix/design/` for the dataplane.

## Who we trust

| Actor | Trust | What they control |
|---|---|---|
| Pod workloads and their traffic | untrusted | any packet on the pod's interface; `connect`/`sendmsg` arguments seen by the cgroup BPF programs |
| Traffic from outside the node | untrusted | any packet arriving on host interfaces, NodePorts, load balancer IPs, tunnels |
| Namespace-scoped Kubernetes users | partly trusted | pods, Services, labels and annotations in their namespaces; namespaced Calico `NetworkPolicy` and Kubernetes `NetworkPolicy`, in the tiers RBAC allows them |
| Cluster admins | trusted | cluster-scoped Calico resources (`GlobalNetworkPolicy`, `Tier`, `IPPool`, `FelixConfiguration`, `BGPConfiguration`, `BGPPeer`, `BGPFilter`), `operator.tigera.io` resources, direct etcd access |
| Root on a node, the kubelet, the container runtime | trusted | CNI, flexvol and CSI invocations, files on the host |
| Calico components talking to each other | trusted once authenticated | Felix ↔ Typha, Felix → Goldmane, whisker-backend → Goldmane, Guardian |

A namespace user must not be able to affect traffic, IP assignment, routing or policy outside their own namespaces, or read another tenant's data, beyond what their RBAC allows.

## Where untrusted input enters, most important first

1. **eBPF dataplane** (`felix/bpf-gpl/*.c`, `*.h`). TC programs on workload, host and tunnel interfaces; XDP on host interfaces; cgroup `connect`/`sendmsg`/`recvmsg` hooks for service load balancing. These parse every packet and implement NAT, conntrack, fragment reassembly, ICMP handling and RPF (`rpf.h`). The verifier bounds memory access, so what matters here is logic: a parsing, NAT, conntrack or RPF error that changes a policy decision, sends traffic to the wrong backend, or lets spoofed or fragmented traffic past policy. `felix/design/` documents the intended behavior.
2. **BPF policy compiler** (`felix/bpf/polprog/`, `felix/bpf/asm/`). Turns rendered rules into BPF bytecode. A miscompiled rule silently inverts allow and deny.
3. **Policy pipeline.** Selector parser (`libcalico-go/lib/selector/`). Namespace scoping of namespaced policies, done by rewriting the user's selector text (`libcalico-go/lib/backend/syncersv1/updateprocessors/`). Calculation graph (`felix/calc/`). Rule rendering (`felix/rules/`, `felix/iptables/`, `felix/nftables/`). A namespaced policy must never select or admit endpoints outside its namespace except through its own `namespaceSelector`. Any parse, quoting or rewrite discrepancy that breaks this is high priority.
4. **Tier authorization.** `apiserver/pkg/registry/projectcalico/authorizer/` and the admission webhook in `webhooks/pkg/rbac/`. A user writing or reading policy in a tier they lack RBAC for can override admin policy.
5. **Certificates and component identity.** Operator CSR signer (`operator/pkg/controller/csr/`), `key-cert-provisioner/`, TLS setup in `crypto/pkg/tls/` and `typha/pkg/tlsutils/`. A pod obtaining a certificate for a Calico component identity, or a peer passing mTLS it should fail, undermines every internal channel.
6. **CNI plugin and IPAM** (`cni-plugin/pkg/`, `libcalico-go/lib/ipam/`). Run as root on the host, driven by the kubelet and by `cni.projectcalico.org/*` annotations that namespace users set. Also load balancer IP assignment from Service annotations (`kube-controllers/pkg/controllers/loadbalancer/`) and label sync in `kube-controllers/`. Taking another workload's IP, or an IP outside what the namespace may use, affects policy identity and traffic.
7. **L7 policy** (`app-policy/checker/`). Calico's own HTTP path normalization and matching for Envoy ext_authz. A path that normalizes differently here than in the application is a policy bypass.
8. **Node agents driven by the kubelet** (`pod2daemon/`): the flexvol driver, CSI driver and per-pod credential sockets. They run as root and write under host paths.
9. **Guardian** (`guardian/pkg/`). Reverse proxy from a management-cluster tunnel into the Kubernetes API and Goldmane, using Guardian's own credentials. Path or target confusion that widens what the tunnel can reach matters.
10. **Lower priority:** Typha's sync protocol (`typha/pkg/syncserver/`); Goldmane, whisker-backend and the whisker UI (flow data includes names and labels chosen by namespace users); confd templates that render datastore fields into BIRD config (`confd/`, `node/filesystem/etc/calico/confd/templates/`); node startup (`node/pkg/`); `calicoctl`.

## Out of scope

- Anything that needs cluster-admin rights, write access to cluster-scoped Calico or operator resources, direct datastore access, or root on a node.
- That `calico-node` runs privileged with host networking and host mounts. This is by design. A concrete escalation path through it is in scope.
- That a node can read the cluster's policy and endpoint state. Felix needs it.
- Kubernetes semantics: traffic to an endpoint that no policy selects is allowed.
- Vulnerabilities in third-party dependencies, unless Calico's own code makes them reachable. Tigera publishes its analysis of these at https://github.com/tigera/vex.
- Upstream code: `third_party/`, `istio/`, and libbpf (cloned into `felix/bpf-gpl/libbpf` at build time). Report those upstream.
- Tests, test harnesses and build or release tooling: `e2e/`, `test/`, `test-tools/`, `*/fv/`, `felix/k8sfv/`, `*/tests/`, `hack/`, `release/`, `devstack/`, `docker/`, `lib/kind/`.
- Generated output: `manifests/` is generated from `charts/`. RBAC or pod security settings there are in scope only with a concrete escalation.

## How we rate severity

- **Critical:** code execution, or root, on a node or in a Calico component, from pod traffic, external traffic or a namespace user. Obtaining a certificate for a Calico component identity from a pod. A policy bypass that defeats default-deny for arbitrary traffic in a default installation.
- **High:** a policy bypass that needs specific but supported conditions (one dataplane mode, a non-default feature, crafted fragments or encapsulation). A namespace user affecting policy, IP assignment or routing in another namespace, or acting in a tier their RBAC does not allow. Disclosure of secrets (keys, tokens, BGP passwords). An mTLS authentication bypass where TLS is configured. An L7 policy bypass.
- **Medium:** denial of service of a node's dataplane or of a Calico component, triggered by pod traffic, external traffic or a namespace user (crashes, crash loops, map or table exhaustion, CPU blow-up). Disclosure of non-secret data, such as flows or policy contents, to someone RBAC should exclude.
- **Low:** issues that need a trusted actor from "Who we trust", and hardening without a demonstrated impact.

A Go panic reachable from untrusted input counts as denial of service, not memory corruption. A BPF program the verifier would reject at load time is not a vulnerability.

## How to exercise it

- Binaries: `/usr/local/bin/calico` (daemons run as `calico component <name>`; `calico component --help` lists them), `calicoctl` and `calico-ipam` (symlinks that dispatch on their own name), `calico-bpf`, and `operator`.
- BPF objects are compiled into `felix/bpf-gpl/bin/` (inspect with `llvm-objdump -d`). The tests in `felix/bpf/ut/` run these programs against crafted packets, but need root and a BPF-capable kernel.
- Unit tests that run offline with plain `go test`: `libcalico-go/lib/selector/...`, `libcalico-go/lib/backend/syncersv1/updateprocessors/...`, `felix/calc/...`, `felix/rules/...`, `felix/bpf/polprog/...`, `felix/iptables/...`, `felix/nftables/...`, `apiserver/pkg/registry/projectcalico/authorizer/...`, `webhooks/pkg/rbac/...`, `app-policy/checker/...`, `operator/pkg/controller/csr/...`, `typha/...`, `goldmane/...`.
- Tests that will not run in the scan: `libcalico-go/lib/ipam` (needs etcd or a Kubernetes API server), `cni-plugin/tests` and the other `fv` suites (need root, network namespaces or a cluster).

## Reports and patches

- Name the dataplane mode (eBPF, nftables, iptables, Windows), the install method (operator or manifests) and any non-default setting the issue depends on.
- For a policy bypass, give the policy, the endpoints and their labels, and the traffic that gets through.
- Patches should add or extend a unit test in the package's existing suite, follow the conventions in `.claude/CLAUDE.md`, and leave generated files to `make generate`.
