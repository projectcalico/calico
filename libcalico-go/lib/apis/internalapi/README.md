# libcalico-go/lib/apis/internalapi

Internal Calico resource types that are not part of the public API (`api/pkg/apis/projectcalico/v3`).

Contains types that are either stored in Kubernetes CRDs but not exposed to end users, and/or types that are used internally
by Calico but are not backed by CRDs (i.e., WorkloadEndpoint which is stored in etcd mode, but backed by a Kubernetes Pod when using
the Kubernetes API for storage).

- **Node** / **WorkloadEndpoint** -- internal representations backed by Kubernetes objects in KDD mode.
- **IPAMBlock**, **IPAMHandle**, **IPAMConfig**, **BlockAffinity** -- IPAM implementation details stored as CRDs but managed exclusively by Calico's IPAM subsystem.
