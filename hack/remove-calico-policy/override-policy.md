# Overriding Calico Policy

This section describes how to override the Calico-enabled Network Policy using higher priority system-wide
network policy.

In the following we describe how to create a `GlobalNetworkPolicy` resource using `kubectl` to allow all
ingress and egress traffic, overriding any other Network Policy that has been configured.

### Requirements / Assumptions

- Calico version v2.5 or higher
- Kubernetes v1.7 or higher
- Calico is running in policy-only mode (without Calico networking)
- Calico is using using the Kubernetes API as the datastore

### Instructions

> **Note:** The following steps assume you have permissions to create custom resources.

#### Override Calico policy to allow all traffic

Create a `GlobalNetworkPolicy` resource by running the following command:

```
kubectl create -f=https://raw.githubusercontent.com/projectcalico/calico/master/hack/remove-calico-policy/global-network-policy-override.yaml
```

#### Revert override to enable Calico policy

To revert the override of Calico policy, delete the `GlobalNetworkPolicy` resource 
responsible for the override by running the following command:

```
kubectl delete -f=https://raw.githubusercontent.com/projectcalico/calico/master/hack/remove-calico-policy/global-network-policy-override.yaml
```
