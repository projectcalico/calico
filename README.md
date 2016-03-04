## Calico Network Policy for Kubernetes 

This repository contains the Calico Kubernetes policy agent, which implements the [Kubernetes v1alpha network policy API](TODO).

See our documentation on [enabling network policy in Kubernetes](https://github.com/projectcalico/calico-containers/blob/master/docs/cni/kubernetes/NetworkPolicy.md) to get started.

## Managing NetworkPolicy objects 
Since `kubectl` does not yet support the creation and deletion of `NetworkPolicy` objects,
this repository comes with a tool named `policy` which can be used to manage policies.  

[See here](policy_tool/README.md)
