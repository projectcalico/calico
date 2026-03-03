# libcalico-go/lib/apis/v1

Legacy v1 API type definitions for the original Calico northbound client API.

Defines resource structs (BGPPeer, HostEndpoint, Policy, IPPool, Profile, Node, WorkloadEndpoint, Tier)
and the `CalicoAPIConfig` for datastore connection configuration. Used by the v1 validator
(`libcalico-go/lib/validator/v1`), the etcd backend, calicoctl's resource loader, and test utilities.

This is not the current API. The public Calico API is defined in `api/pkg/apis/projectcalico/v3/`.
