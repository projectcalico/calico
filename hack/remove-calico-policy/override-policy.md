# Overriding Calico Policy

This section describes how to override the Calico-enabled Network Policy using higher priority system-wide
network policy.

In the following we describe how to create a `SystemNetworkPolicy` resource using `kubectl` to allow all
ingress and egress traffic, overriding any other Network Policy that has been configured.

### Requirements / Assumptions

- Calico version v2.3 or higher
- Kubernetes v1.6 or higher
- Calico is running in policy-only mode (without Calico networking)
- Calico is using using the Kubernetes API as the datastore

### Instructions

> **Note:** The following steps assume you have permissions to create resources in the `kube-system` namespace.

#### Override Calico policy to allow all traffic

Create a `SystemNetworkPolicy` resource by running the following command:

```
kubectl create -n=kube-system -f=https://raw.githubusercontent.com/projectcalico/calico/master/hack/remove-calico-policy/system-network-policy-override.yaml
```

#### Revert override to enable Calico policy

To revert the override of Calico policy, delete the `SystemNetworkPolicy` resource 
responsible for the override by running the following command:

```
kubectl delete -n=kube-system -f=https://raw.githubusercontent.com/projectcalico/calico/master/hack/remove-calico-policy/system-network-policy-override.yaml
```
