### Install {{site.prodname}}
{{site.prodname}} can be installed on Kubernetes using Kubernetes resources (DaemonSets, etc).

The {{site.prodname}} self-hosted installation consists of three objects in the `kube-system` Namespace:

- A `ConfigMap` which contains the {{site.prodname}} configuration.
- A `DaemonSet` which installs the `{{site.nodecontainer}}` pod and CNI plugin.
- A `ReplicaSet` which installs the `calico/kube-policy-controller` pod.

Install the {{site.prodname}} manifest:

```shell
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/calico.yaml
```

Issue the following command.

```shell
kubectl get pods --namespace=kube-system
```

You should see the pods start in the `kube-system` namespace.

```bash
NAME                             READY     STATUS    RESTARTS   AGE
{{site.noderunning}}-1f4ih                2/2       Running   0          1m
{{site.noderunning}}-hor7x                2/2       Running   0          1m
{{site.noderunning}}-si5br                2/2       Running   0          1m
calico-kube-controller-so4gl    1/1       Running   0          1m
  info: 1 completed object(s) was(were) not shown in pods list. Pass --show-all to see all objects.
```
{: .no-select-button}

### Install DNS

To install KubeDNS, use the provided manifest.  This enables Kubernetes Service discovery.

```shell
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/manifests/kubedns.yaml
```
