
## Create Custom Resource Definitions

crds.yaml is applied before running the tests to initialize CRDs (CustomResourceDefinitions)
for the Kubernetes backend.
This manifest is applied in the Makefile once kubernetes API server is running.
crds.yaml creates the following CRDs:
  - FelixConfig
  - BGPPeer
  - BGPConfig
  - IPPool
  - GlobalNetworkPolicy
  - ClusterInfo
  - NetworkPolicy

These CRDs must be created in advance for any Calico deployment with Kubernetes backend,
typically as part of the same manifest used to setup Calico.

## Create Mock Nodes

mock-node.yaml creates mock node object for the tests.

## Create Namespaces

`NetworkPolicy` CRD is a Namespace scoped resource and requires some Kubernetes Namespaces
to exists before it can be used so.
