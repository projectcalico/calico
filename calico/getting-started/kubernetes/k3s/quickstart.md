---
title: Quickstart for Calico on K3s
description: Install Calico on a single-node K3s cluster for testing or development in under 5 minutes.
canonical_url: '/getting-started/kubernetes/k3s/quickstart'
---

### Big picture

This quickstart gets you a single-node K3s cluster with {{site.prodname}}
in approximately 5 minutes. You can use this cluster for testing and
development.

### Value

Use this quickstart to quickly and easily try {{site.prodname}} features. To deploy a cluster suitable for production, refer to [Multi-node install]({{ site.baseurl }}/getting-started/kubernetes/k3s/multi-node-install).

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:VXLAN,Routing:Calico,Datastore:Kubernetes' %}

### Before you begin

- Make sure you have a linux host that meets the following requirements
   - x86-64 processor
   - 1CPU
   - 1GB Ram
   - 10GB free disk space
   - Ubuntu 16.04 (amd64), Ubuntu 18.04 (amd64), Ubuntu 20.04 (amd64)

> **Note**: K3s supports ARM processors too, this quickstart was tested against x86-64 processor environment.
> For more detail please visit {% include open-new-window.html text='this link' url='https://rancher.com/docs/k3s/latest/en/installation/installation-requirements/#operating-systems' %}.
{: .alert .alert-info}

### How to
#### Create a single-node K3s cluster

- Initialize the master using the following command.

```bash
curl -sfL https://get.k3s.io | K3S_KUBECONFIG_MODE="644" INSTALL_K3S_EXEC="--flannel-backend=none --cluster-cidr=192.168.0.0/16 --disable-network-policy --disable=traefik" sh -
```

> **Note**: If 192.168.0.0/16 is already in use within your network you must select a different pod network
> CIDR by replacing 192.168.0.0/16 in the above command. 
> 
> **Note**: K3s installer generates `kubeconfig` file in `etc` directory with limited permissions, using `K3S_KUBECONFIG_MODE` environment
> you are assigning necessary permissions to the file and make it accessible for other users.
{: .alert .alert-danger}

#### Install {{site.prodname}}

   {% tabs %}
   <label:Operator,active:true>
   <%
Install the {{site.prodname}} operator and custom resource definitions.

   ```bash
   kubectl create -f {{site.data.versions.first.manifests_url}}/manifests/tigera-operator.yaml
   ```

Install {{site.prodname}} by creating the necessary custom resource. For more information on configuration options available in this manifest, see [the installation reference]({{site.baseurl}}/reference/installation/api).

   ```bash
   kubectl create -f {{site.data.versions.first.manifests_url}}/manifests/custom-resources.yaml
   ```

   > **Note**: Before creating this manifest, read its contents and make sure its settings are correct for your environment. For example,
   > you may need to change the default IP pool CIDR to match your pod network CIDR.
   {: .alert .alert-info}
   
   %>
   <label:Manifest>
   <%
   Install {{site.prodname}} by using the following command.

   ```bash
   kubectl apply -f {{site.data.versions.first.manifests_url}}/manifests/calico.yaml
   ```

   > **Note**: You can also
   > [view the YAML in a new tab]({{site.data.versions.first.manifests_url}}/manifests/calico.yaml){:target="_blank"}.
   {: .alert .alert-info}

   You should see the following output.

   ```
    configmap/calico-config created
    customresourcedefinition.apiextensions.k8s.io/bgpconfigurations.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/bgppeers.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/blockaffinities.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/clusterinformations.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/felixconfigurations.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/globalnetworkpolicies.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/globalnetworksets.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/hostendpoints.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/ipamblocks.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/ipamconfigs.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/ipamhandles.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/ippools.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/kubecontrollersconfigurations.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/networkpolicies.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/networksets.crd.projectcalico.org created
    clusterrole.rbac.authorization.k8s.io/calico-kube-controllers created
    clusterrolebinding.rbac.authorization.k8s.io/calico-kube-controllers created
    clusterrole.rbac.authorization.k8s.io/calico-node created
    clusterrolebinding.rbac.authorization.k8s.io/calico-node created
    daemonset.apps/calico-node created
    serviceaccount/calico-node created
    deployment.apps/calico-kube-controllers created
    serviceaccount/calico-kube-controllers created
   ```
   {: .no-select-button}

   %>
   {% endtabs %}

#### Final checks   

1. Confirm that all of the pods are running using the following command.

```bash
watch kubectl get pods --all-namespaces
```

Wait until each pod shows the `STATUS` of `Running`.

{% tabs %}
<label:Operator,active:true>
<%

```
NAMESPACE         NAME                                      READY   STATUS    RESTARTS   AGE
tigera-operator   tigera-operator-c9cf5b94d-gj9qp           1/1     Running   0          107s
calico-system     calico-typha-7dcd87597-npqsf              1/1     Running   0          88s
calico-system     calico-node-rdwwz                         1/1     Running   0          88s
kube-system       local-path-provisioner-6d59f47c7-4q8l2    1/1     Running   0          2m14s
kube-system       metrics-server-7566d596c8-xf66d           1/1     Running   0          2m14s
kube-system       coredns-8655855d6-wfdbm                   1/1     Running   0          2m14s
calico-system     calico-kube-controllers-89df8c6f8-7hxc5   1/1     Running   0          87s
```
{: .no-select-button}
%>
<label:Manifest>
<%

```
NAMESPACE     NAME                                       READY   STATUS    RESTARTS   AGE
kube-system   {{site.noderunning}}-9hn9z                          1/1     Running   0          23m
kube-system   local-path-provisioner-6d59f47c7-drznc     1/1     Running   0          38m
kube-system   calico-kube-controllers-789f6df884-928lt   1/1     Running   0          23m
kube-system   metrics-server-7566d596c8-qxlfz            1/1     Running   0          38m
kube-system   coredns-8655855d6-blzl5                    1/1     Running   0          38m
```
{: .no-select-button}
%>
{% endtabs %}

1. Press CTRL+C to exit `watch`.

2. Confirm that you now have a node in your cluster with the
following command.

```bash
kubectl get nodes -o wide
```

It should return something like the following.

```
NAME         STATUS   ROLES    AGE   VERSION        INTERNAL-IP    EXTERNAL-IP   OS-IMAGE             KERNEL-VERSION       CONTAINER-RUNTIME
k3s-master   Ready    master   40m   v1.18.2+k3s1   172.16.2.128   <none>        Ubuntu 18.04.3 LTS   4.15.0-101-generic   containerd://1.3.3-k3s2
```
{: .no-select-button}

Congratulations! You now have a single-node K3s cluster
equipped with {{site.prodname}}.

### Next steps
- Try running the [Kubernetes Network policy demo]({{ site.baseurl }}/security/tutorials/kubernetes-policy-demo/kubernetes-demo) to see live graphical view of network policy in action
