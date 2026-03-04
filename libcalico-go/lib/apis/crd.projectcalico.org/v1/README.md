# libcalico-go/lib/apis/crd.projectcalico.org/v1

Kubernetes CRD type definitions for the `crd.projectcalico.org` API group. These are the
kubebuilder-annotated structs that define the actual CRD schemas stored in the Kubernetes API server.

Covers both user-facing resources (NetworkPolicy, GlobalNetworkPolicy, BGPPeer, IPPool, Tier,
FelixConfiguration, etc.) and internal IPAM resources (IPAMBlock, IPAMHandle, IPAMConfig,
BlockAffinity). The IPAM types embed their specs from the `internalapi` package.

Used by the Kubernetes backend (`libcalico-go/lib/backend/k8s`) and its raw CRD client for
direct CRD operations.

## Generating CRDs

Calico APIs that are backed using CRDs should be added here so that auto-generation picks up
the API. See other structs in this directory as an example.

Once added, run `make gen-crds` in the root of this repository to update the custom resource
definition YAMLs.
