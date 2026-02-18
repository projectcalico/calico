# libcalico-go/lib/apis/internalapi

Internal Calico resource types that are not part of the public API (`api/pkg/apis/projectcalico/v3`).

Contains types that need Kubernetes CRD storage but are either internal-only or carry additional
fields beyond what the public API exposes:

- **Node** / **WorkloadEndpoint** -- internal representations with fields like VXLAN tunnel
  addresses, wireguard keys, QoS controls, and pod CIDRs that are not user-facing.
- **IPAMBlock**, **IPAMHandle**, **IPAMConfig**, **BlockAffinity** -- IPAM implementation
  details stored as CRDs but managed exclusively by Calico's IPAM subsystem.

Widely used across felix, node, kube-controllers, cni-plugin, calicoctl, typha, confd,
and libcalico-go itself.
