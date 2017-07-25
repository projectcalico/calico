### Install Calico
Calico can be installed on Kubernetes using Kubernetes resources (DaemonSets, etc).

The Calico self-hosted installation consists of three objects in the `kube-system` Namespace:

- A `ConfigMap` which contains the Calico configuration.
- A `DaemonSet` which installs the `calico/node` pod and CNI plugin.
- A `ReplicaSet` which installs the `calico/kube-policy-controller` pod.

Install the Calico manifest:

```shell
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/calico.yaml
```

You should see the pods start in the `kube-system` Namespace:

```shell
$ kubectl get pods --namespace=kube-system
NAME                             READY     STATUS    RESTARTS   AGE
calico-node-1f4ih                2/2       Running   0          1m
calico-node-hor7x                2/2       Running   0          1m
calico-node-si5br                2/2       Running   0          1m
calico-policy-controller-so4gl   1/1       Running   0          1m
  info: 1 completed object(s) was(were) not shown in pods list. Pass --show-all to see all objects.
```

### Install DNS

To install KubeDNS, use the provided manifest.  This enables Kubernetes Service discovery.

```shell
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/manifests/skydns.yaml
```
