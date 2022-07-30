---
title: K3s multi-node install  
description: Install Calico on a multi node K3s cluster for testing or development.
canonical_url: '/getting-started/kubernetes/k3s/multi-node-install'
---

### Big picture

This tutorial gets you a multi node K3s cluster with {{site.prodname}} in approximately 10 minutes. 

### Value

K3s is a lightweight implementation of Kubernetes packaged as a single binary.

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:VXLAN,Routing:Calico,Datastore:Kubernetes' %}

### Before you begin

- Make sure you have a linux host that meets the following requirements
   - x86-64 processor
   - 1CPU
   - 1GB Ram
   - 10GB free disk space
   - Ubuntu 16.04 (amd64), Ubuntu 18.04 (amd64), Ubuntu 20.04 (amd64)
   
> **Note**: K3s supports ARM processors too, this tutorial was tested against x86-64 processor environment.
> For more detail please visit {% include open-new-window.html text='this link' url='https://rancher.com/docs/k3s/latest/en/installation/installation-requirements/#operating-systems' %}.
{: .alert .alert-info}

### How to

#### Initializing master instance
   K3s installation script can be modified by {% include open-new-window.html text='environment variables' url='https://rancher.com/docs/k3s/latest/en/installation/install-options/#options-for-installation-with-script' %}. Here you are providing some extra arguments in order to disable `flannel`, disable k3s default network policy and change the pod ip CIDR.

   > **Note**: Full list of arguments can be viewed {% include open-new-window.html text='at this link' url='https://rancher.com/docs/k3s/latest/en/installation/install-options/server-config/' %}.
   {: .alert .alert-info}

    curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--flannel-backend=none --disable-network-policy --cluster-cidr=192.168.0.0/16" sh -

   > **Note**: If 192.168.0.0/16 is already in use within your network you must select a different pod network
   > CIDR by replacing 192.168.0.0/16 in the above command. 
   {: .alert .alert-danger}

#### Enable remote access to your K3s instance

   In order to setup remote access to your cluster first ensure you have installed `kubectl` on your system.

   > **Note**: If you are not sure how to install kubectl in your OS {% include open-new-window.html text='visit this link' url='https://kubernetes.io/docs/tasks/tools/install-kubectl/' %}.
   {: .alert .alert-info}

   K3s stores a kubeconfig file in your server at `/etc/rancher/k3s/k3s.yaml`, copy all the content of `k3s.yaml` from your server into `~/.kube/config` on the system that you like to have remote access to the cluster.

#### Add extra nodes to K3s cluster
   
   In order to add additional nodes to your cluster you need two piece of information.
   - `K3S_URL` which is going to be your main node ip address. 
   - `K3S_TOKEN` which is stored in `/var/lib/rancher/k3s/server/node-token` file in main Node [(Step 1)](#initializing-master-instance).
   Execute following command in your node instance and join it to the cluster.

   > **Note**: Remember to change `serverip` and `mytoken`.
   {: .alert .alert-info}

   ```bash
   curl -sfL https://get.k3s.io | K3S_URL=https://serverip:6443 K3S_TOKEN=mytoken sh -
   ```

#### Install {{site.prodname}}
   {% tabs tab-group:grp1 %}
   <label:Operator,active:true>
   <%
Install the {{site.prodname}} operator and custom resource definitions.

   ```bash
   kubectl create -f {{ "/manifests/tigera-operator.yaml" | absolute_url }}
   ```
   
   > **Note**: Due to the large size of the CRD bundle, `kubectl apply` might exceed request limits. In stead, use `kubectl create` or `kubectl replace`.
   {: .alert .alert-info}

Install {{site.prodname}} by creating the necessary custom resource. For more information on configuration options available in this manifest, see [the installation reference]({{site.baseurl}}/reference/installation/api).

   ```bash
   kubectl create -f {{ "/manifests/custom-resources.yaml" | absolute_url }}
   ```

   > **Note**: Before creating this manifest, read its contents and make sure its settings are correct for your environment. For example,
   > you may need to change the default IP pool CIDR to match your pod network CIDR.
   {: .alert .alert-info}
   
   %>
   <label:Manifest>
   <%
   Install {{site.prodname}} by using the following command.

   ```bash
   kubectl apply -f {{ "/manifests/calico.yaml" | absolute_url }}
   ```

   > **Note**: You can also
   > [view the YAML in a new tab]({{ "/manifests/calico.yaml" | absolute_url }}){:target="_blank"}.
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


   
#### Check the installation
   
1. Confirm that all of the pods are running using the following command.

{% tabs tab-group:grp1 %}
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
kube-system   {{site.noderunning}}-9hn9z                    1/1     Running   0          23m
kube-system   local-path-provisioner-6d59f47c7-drznc     1/1     Running   0          38m
kube-system   calico-kube-controllers-789f6df884-928lt   1/1     Running   0          23m
kube-system   metrics-server-7566d596c8-qxlfz            1/1     Running   0          38m
kube-system   coredns-8655855d6-blzl5                    1/1     Running   0          38m
```
{: .no-select-button}
%>
{% endtabs %}

1. Confirm that you now have two nodes in your cluster with the following command.

   ```bash
   kubectl get nodes -o wide
   ```

   It should return something like the following.

   ```
   NAME         STATUS   ROLES    AGE   VERSION        INTERNAL-IP    EXTERNAL-IP   OS-IMAGE             KERNEL-VERSION       CONTAINER-RUNTIME
   k3s-master   Ready    master   40m   v1.18.2+k3s1   172.16.2.128   <none>        Ubuntu 18.04.3 LTS   4.15.0-101-generic   containerd://1.3.3-k3s2
   k3s-node1    Ready    <none>   30m   v1.18.2+k3s1   172.16.2.129   <none>        Ubuntu 18.04.3 LTS   4.15.0-101-generic   containerd://1.3.3-k3s2
   ```
   {: .no-select-button}

Congratulations! You now have a multi node K3s cluster
equipped with {{site.prodname}} and Traefik.

### Next steps
- Try running the [Kubernetes Network policy demo]({{ site.baseurl }}/security/tutorials/kubernetes-policy-demo/kubernetes-demo) to see live graphical view of network policy in action
