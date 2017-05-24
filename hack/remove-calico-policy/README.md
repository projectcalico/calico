# Disabling and Removing Calico Policy

Calico policy can be disabled and removed for troubleshooting purposes or in emergency situations using the following steps.


### Requirements

- Calico node version `v1.0.0` or higher
- Kubernetes `v1.6` or higher
- Calico running in policy-only mode

### Removing policy on a single node

1. Stop and remove the `calico-node` DaemonSet/container/service on the Node to prevent network policy from being (re)programmed.

2. Run the provided script `remove-calico-policy.sh` on that specific Node (either manually or using DaemonSet with `nodeSelector`)
    a. If Calico is Masquerading the outgoing traffic then you need to set the `CLUSTER_CIDR` environment variable or update the DaemonSet
      `calico-remove-iptables.yaml` Spec field `CLUSTER_CIDR` to the appropriate cluster CIDR. (By default, this script won't create Masquerade rules if `CLUSTER_CIDR` is not specefied.)
    b. (This step is only required if you're running the DaemonSet to remove the policy) Create the ConfigMap with the script `remove-calico-policy.sh`, found in this directory to remove
       the Calico iptables rules (this ConfigMap will be used in the DaemonSet in the following step).
        `kubectl create configmap remove-calico-policy-config --namespace=kube-system --from-file=/path/to/remove-calico-policy.sh`
    c. Run the script or DaemonSet `calico-remove-iptables.yaml` with the appropriate `nodeSelector` value to select the correct node.

### Removing policy on all nodes
1. Stop and remove the `calico-node` DaemonSet/container/service on each Node to prevent network policy from being (re)programmed.
   For example, if you have `calico-node` deployed as DaemonSet, use the following command to remove it:
    `kubectl delete daemonset calico-node -n kube-system`

2. Create a ConfigMap with the script `remove-calico-policy.sh`, found in this directory to remove
   the Calico iptables rules (this ConfigMap will be used in the DaemonSet in the following step).
    `kubectl create configmap remove-calico-policy-config --namespace=kube-system --from-file=/path/to/remove-calico-policy.sh`

3. Run the DaemonSet:
    a. If Calico is Masquerading the outgoing traffic then you need to update the DaemonSet `calico-remove-iptables.yaml` Spec field `CLUSTER_CIDR` 
       to the appropriate cluster CIDR. (By default, this script won't create Masquerade rules if `CLUSTER_CIDR` is not specefied.)
    b. Remove all Calico iptables chains by running the following on each Node (e.g. using a privileged DaemonSet with host networking):
        `kubectl apply -f calico-remove-iptables.yaml`