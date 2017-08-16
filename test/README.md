
## Create Custom Resource Definitions

crds.yaml is applied before running the tests to initialize CRDs (CustomResourceDefinitions)
for the Kubernetes backend.
This manifest is applied in the Makefile once kubernetes API server is running.
crds.yaml creates the following CRDs:
  - GlobalFelixConfig
  - GlobalBGPPeer
  - GlobalBGPConfig
  - IPPool
  - GlobalNetworkPolicy

These CRDs must be created in advance for any Calico deployment with Kubernetes backend,
typically as part of the same manifest used to setup Calico.


## Create Mock Nodes

mock-node.yaml creates mock node object for the tests.