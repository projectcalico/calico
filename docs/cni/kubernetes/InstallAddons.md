<!--- master only -->
> ![warning](../../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.21.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Installing Calico and Cluster Addons 
## Install Calico
Calico can be installed on Kubernetes using Kubernetes resources (DaemonSets, etc).

The Calico self-hosted installation consists of three objects in the `kube-system` Namespace:
- A `ConfigMap` which contains the Calico configuration.
- A `DaemonSet` which installs the `calico/node` pod and CNI plugin.
- A `ReplicaSet` which installs the `calico/kube-policy-controller` pod.

To intall these components:
```
kubectl create -f manifests/calico-config.yaml
kubectl create -f manifests/calico-hosted.yaml
```

You should see the containers start in the `kube-system` Namespace:

```
$ kubectl get pods --namespace=kube-system
NAME                             READY     STATUS    RESTARTS   AGE
calico-node-ctwm7                2/2       Running   0          4m
calico-node-w03mn                2/2       Running   0          4m
calico-policy-controller-lo2hf   1/1       Running   0          4m
```

## Install DNS
To install KubeDNS, use the provided manifest.  This enables Kubernetes Service discovery.

```
kubectl create -f manifests/skydns.yaml
```

## Next Steps
You should now have a fully functioning Kubernetes cluster using Calico for networking.  You're ready to use your cluster.

We recommend you try using [Calico for Kubernetes NetworkPolicy](simple-policy-demo/README.md).
