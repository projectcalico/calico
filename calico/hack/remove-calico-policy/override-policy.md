# Overriding Calico Policy

This section describes how to override the Calico-enabled Network Policy using higher priority system-wide
network policy.

In the following we describe how to create a `GlobalNetworkPolicy` (`SystemNetworkPolicy` for Calico `v2.4.x` or older) 
resource using `kubectl` to allow all ingress and egress traffic, overriding any other Network Policy that has been configured.

### Requirements / Assumptions

- Calico version `v2.3` or higher
- Kubernetes `v1.6` or higher
- Calico is running in policy-only mode (without Calico networking)
- Calico is using using the Kubernetes API as the datastore

### Instructions

> **Note:** The following steps assume you have permissions to create custom resources.

#### Override Calico policy to allow all traffic

Create a policy-override resource by running the following command:

For Calico `v2.5.x` or higher:

```
kubectl create -f=https://raw.githubusercontent.com/projectcalico/calico/master/calico/hack/remove-calico-policy/global-network-policy-override.yaml
```

For Calico `v2.3.x` and `v2.4.x`:

```
kubectl create -f=https://raw.githubusercontent.com/projectcalico/calico/master/calico/hack/remove-calico-policy/system-network-policy-override.yaml
```

#### Revert override to enable Calico policy

To revert the override of Calico policy, delete the policy-override resource 
responsible for the override by running the following command:

For Calico `v2.5.x` or higher:

```
kubectl delete -f=https://raw.githubusercontent.com/projectcalico/calico/master/calico/hack/remove-calico-policy/global-network-policy-override.yaml
```

For Calico `v2.3.x` and `v2.4.x`:

```
kubectl delete -f=https://raw.githubusercontent.com/projectcalico/calico/master/calico/hack/remove-calico-policy/system-network-policy-override.yaml
```