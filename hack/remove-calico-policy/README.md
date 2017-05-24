# Disabling and removing Calico policy

1. Stop and remove the calico-node Pod on each Node to prevent network policy from being (re)programmed.
    `kubectl delete daemonset calico-node -n kube-system`

2. Create a configmap with the bash script to remove the Calico iptables rules (this configmap will be used in the DaemonSet in the following step).
    `kubectl create configmap remove-calico-policy-config --namespace=kube-system --from-file=/path/to/remove-calico-policy.sh`

3. Remove all Calico iptables chains by running the following on each Node (e.g. using a privileged DaemonSet with host networking) or on a specific problem Node:
    `kubectl apply -f calico-remove-iptables.yaml`



