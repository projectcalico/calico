## Calico Network Policy for Kubernetes 

This repository contains the Calico Kubernetes policy agent, which implements the [Kubernetes v1alpha network policy API](TODO).

See our documentation on [enabling network policy in Kubernetes](https://github.com/projectcalico/calico-containers/blob/master/docs/cni/kubernetes/NetworkPolicy.md) to get started.

## Managing NetworkPolicy objects 
Since `kubectl` does not yet support the creation and deletion of `NetworkPolicy` objects,
this repository comes with a tool named `policy` which can be used to manage policies.  
```
wget https://github.com/projectcalico/k8s-policy/releases/download/v0.1.0/policy
```

It is configurable via environment variables. 
```
export KUBE_API_ROOT=http://localhost:8080
export KUBE_AUTH_TOKEN="<auth_token>"
```
> You can find your auth token using `kubectl describe secret`

To create a new network policy from a file:
```
cat policy.yaml | policy create
```

To delete a network policy:
```
policy delete <namespace> <policy-name>
```

To list all `NetworkPolicy` objects:
```
policy list
```

To get details about a specific `NetworkPolicy`:
```
policy get <namespace> <policy-name>
```
