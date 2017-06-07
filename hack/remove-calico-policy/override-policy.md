# Overriding Calico Policy

This section describes how to override the Calico-enabled Network Policy using higher priority system-wide
network policy.

In the following we describe how to create a `SystemNetworkPolicy` resource using `kubectl` to allow all
ingress and egress traffic, overriding any other Network Policy that has been configured.

### Requirements / Assumptions

- Calico version v2.3 or higher
- Kubernetes v1.6 or higher
- These steps assume Calico is running in policy-only mode (without Calico networking)

### Instructions

> **Note:** The following steps assume you have permissions to create resources in the `kube-system` namespace.

Create a `SystemNetworkPolicy` resource by running the following commands:

```
kubectl create -n=kube-system -f=https://raw.githubusercontent.com/projectcalico/calico/master/hack/remove-calico-policy/system-network-policy-override.yaml
```
