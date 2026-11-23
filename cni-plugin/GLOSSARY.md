# CNI plugin glossary

This file extends the [root GLOSSARY.md](../GLOSSARY.md). It covers the `calico` network plugin. The calico-ipam terms (sandbox, prior sandbox, sandbox handover, sandbox handle, kept addresses, IPAM lock) are in [design/ipam/GLOSSARY.md](../design/ipam/GLOSSARY.md).

## Building blocks

Top layer of the CNI plugin binary.

| Building block | Code | Responsible for |
|---|---|---|
| Name dispatcher | `cni-plugin/cmd/calico/calico.go` (`main`) | Choosing the `calico` network plugin or the calico-ipam plugin from the binary's name. |
| Network plugin | `cni-plugin/pkg/plugin/plugin.go` (`cmdAdd`, `cmdDel`) | Parsing NetConf, finding or creating the WorkloadEndpoint, calling an IPAM plugin, then a CNI dataplane. |
| Kubernetes ADD and DEL | `cni-plugin/pkg/k8s/k8s.go` (`CmdAddK8s`, `CmdDelK8s`) | The Kubernetes path: IPAM annotations, address handover across sandboxes, the WorkloadEndpoint write, the policy wait. |
| CNI dataplane | `cni-plugin/pkg/dataplane/dataplane.go` (`Dataplane`) | Creating the host and container interfaces and routes for one sandbox. |
| Endpoint wait | `cni-plugin/pkg/wait/wait.go` (`ForEndpointReadyWithTimeout`) | Holding ADD until Felix writes the endpoint's status file. |

Layers inside the network plugin and its helpers.

| Building block | Code | Responsible for |
|---|---|---|
| Linux CNI dataplane | `cni-plugin/pkg/dataplane/linux/dataplane_linux.go` (`DoNetworking`) | A veth pair or a netkit pair between the host and the container namespace. |
| Windows CNI dataplane | `cni-plugin/pkg/dataplane/windows/dataplane_windows.go` (`DoNetworking`) | Windows HNS networks and endpoints. |
| gRPC CNI dataplane | `cni-plugin/pkg/dataplane/grpc/grpc_dataplane.go` (`NewGrpcDataplane`) | Handing interface setup to an external dataplane over gRPC. |
| Platform shims | `cni-plugin/internal/pkg/utils/network_windows.go` (`EnsureVXLANTunnelAddr`, `CheckForSpuriousDockerAdd`, `RegisterDeletedWep`) | Windows-only VXLAN tunnel address and duplicate-ADD handling. The Linux versions do nothing. |
| Host-local IPAM support | `cni-plugin/internal/pkg/utils/utils.go` (`ReplaceHostLocalIPAMPodCIDRs`) | Substituting the node's pod CIDRs for `usePodCidr` when a non-Calico IPAM plugin is in use. |

## Terms

Terms defined in the [root glossary](../GLOSSARY.md) that apply in this component:

- [Endpoint status directory](../GLOSSARY.md#endpoint-status-directory)
- [Endpoint status file](../GLOSSARY.md#endpoint-status-file)

**Network plugin**:
The `calico` CNI program that kubelet invokes for a pod's network. It creates the WorkloadEndpoint, calls an IPAM plugin, then calls a CNI dataplane.
Code: `cni-plugin/pkg/plugin/plugin.go` (`Main`).
_Avoid_: the CNI (ambiguous), main CNI

**NetConf**:
The CNI network configuration JSON that the plugin parses on every call.
Code: `cni-plugin/pkg/types/types.go` (`NetConf`).
_Avoid_: CNI config (that also means the conflist file)

**Feature control**:
The NetConf switches that unlock `ipAddrsNoIpam` and `floatingIPs`.
Code: `cni-plugin/pkg/types/types.go` (`FeatureControl`).

**WEP identifiers**:
The node name, orchestrator, pod, container ID and interface name that together name a WorkloadEndpoint.
Code: `cni-plugin/internal/pkg/utils/utils.go` (`WEPIdentifiers`).

**WEP name prefix**:
A WorkloadEndpoint name without its interface part, used to list every endpoint a pod already has.
Code: `cni-plugin/pkg/plugin/plugin.go` (`CalculateWorkloadEndpointName`).

**CNI dataplane**:
The pluggable piece of the network plugin that creates the host and container interfaces and routes for one sandbox. Three exist: Linux, Windows and gRPC.
Code: `cni-plugin/pkg/dataplane/dataplane.go` (`Dataplane`, `GetDataplane`).
_Avoid_: Felix dataplane, dataplane (on its own)

**gRPC CNI dataplane**:
The CNI dataplane selected by `dataplane_options.type` set to `grpc`, which passes ADD and DEL to an external server that sets up the interfaces.
Code: `cni-plugin/pkg/dataplane/grpc/proto/cnibackend.proto` (`CniDataplane`).

**Readiness gates**:
The NetConf list of HTTP URLs that the plugin polls before ADD proceeds.
Code: `cni-plugin/pkg/types/types.go` (`ReadinessGates`), `cni-plugin/pkg/plugin/plugin.go` (`pollEndpointReadiness`).
_Avoid_: readinessGates (that is a Pod field)

**`ForEndpointReadyWithTimeout`**:
The ADD step, on when `policy_setup_timeout_seconds` is positive, that holds the pod's start until Felix writes the endpoint status file.
Code: `cni-plugin/pkg/wait/wait.go` (`ForEndpointReadyWithTimeout`), `cni-plugin/pkg/types/types.go` (`PolicySetupTimeoutSeconds`).

**Device type**:
The NetConf choice of interface pair for a pod: a veth pair, or a netkit pair on kernels that support it.
Code: `cni-plugin/pkg/types/types.go` (`DeviceTypeNetkit`).
