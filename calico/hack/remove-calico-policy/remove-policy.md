# Disabling and Removing Calico Policy

This guide explains how to disable and remove Calico policy from a running cluster. These steps are intended as a
last resort should it appear that Calico policy is not functioning properly on a production system.

The steps in this directory are specific to clusters running on GCE using the
Kubernetes `cluster/kube-up.sh` script, but can be generalized to other Calico deployments.

Calico policy can be disabled and removed for troubleshooting purposes or in emergency situations using the following steps.

### Requirements / Assumptions

- Calico version v2.2 or higher
- Kubernetes v1.6 or higher
- These steps assume Calico is running in policy-only mode (without Calico networking)

### Building

To build the `calico/iptables-remover` Docker image used by the DaemonSet:

```
curl https://raw.githubusercontent.com/projectcalico/calico/master/calico/hack/remove-calico-policy/Dockerfile -o Dockerfile
docker build -t calico/iptables-remover .
```

The image is hosted on DockerHub at `calico/iptables-remover:latest`

### Instructions

> **Note:** The following steps assume you're running [Calico on GCE via kube-up](https://github.com/kubernetes/kubernetes/tree/master/cluster/addons/calico-policy-controller){:target="_blank"}
using the add-on manager and that you have permissions to create resources in the `kube-system` namespace.

#### Disabling and Removing Calico Policy

To fully disable and remove Calico policy from your cluster, follow the steps below.

##### 1. Stop Felix on the nodes

First, you must stop the Felix agent running on the nodes in question. You can do this by removing the
`projectcalico.org/ds-ready: "true"` label from the nodes.

To remove from all nodes:

```
kubectl label nodes --all projectcalico.org/ds-ready-
```

Then, wait until all the `calico-node-xxxx` pods in the `kube-system` Namespace have terminated.

##### 2. Remove any programmed policy from the nodes

To remove any programmed policy from the nodes, follow the steps below to deploy the DaemonSet using the manifest
provided in this directory. The DaemonSet runs on all nodes without the
`projectcalico.org/ds-ready: "true"` label, and removes any Calico iptables rules on the node.

The DaemonSet relies on a ConfigMap containing [the script to execute](remove-calico-policy.sh) from this
directory. First, create the ConfigMap:

```
curl https://raw.githubusercontent.com/projectcalico/calico/master/calico/hack/remove-calico-policy/remove-calico-policy.sh -o remove-calico-policy.sh
kubectl create configmap remove-calico-policy-config -n=kube-system --from-file=./remove-calico-policy.sh
```

Then, deploy the DaemonSet:

```
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/master/calico/hack/remove-calico-policy/iptables-remover-ds.yaml
```

#### Revert: Re-enabling Calico Policy

To revert the disabling and removal of Calico policy, follow the steps below.

##### 1. Delete the policy-removal DaemonSet and ConfigMap

Remove the policy-removal Daemonset and the ConfigMap:

```
kubectl delete -f https://raw.githubusercontent.com/projectcalico/calico/master/calico/hack/remove-calico-policy/iptables-remover-ds.yaml
kubectl delete configmap remove-calico-policy-config -n=kube-system
```

##### 2. Restart Felix on the nodes

To restart the Felix agent on each node, label the nodes with 
`projectcalico.org/ds-ready: "true"`.

```
kubectl label nodes --all projectcalico.org/ds-ready=true
```

