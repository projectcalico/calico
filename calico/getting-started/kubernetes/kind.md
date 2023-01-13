---
title: Kind multi-node install
description: Enable Calico on a single/multi-node Kind cluster for testing or development in approximately 10 minutes.
canonical_url: '/getting-started/kubernetes/kind'
---

### Big picture

This tutorial gets you a multi node Kind cluster with Calico in approximately 10 minutes.


### Value

kind is a tool for running local Kubernetes clusters using Docker container "nodes".

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:VXLAN,Routing:Calico,Datastore:Kubernetes' %}

### Before you begin
- Ensure Docker is installed
- Install, but do not create cluster, kind. {% include open-new-window.html text='How to install Kind' url='https://kind.sigs.k8s.io/docs/user/quick-start/#installation' %}
- Install kubectl.{% include open-new-window.html text='How to install kubectl' url='https://kubernetes.io/docs/tasks/tools/install-kubectl/' %}

### How to

#### Create a multi-node kind cluster

KIND ships with a simple networking implementation ("kindnetd") based around standard CNI plugins (`ptp`, `host-local`, …) and simple netlink routes. You need to disable the default CNI in order to use Calico CNI.

Kind cluster creation can be modified by {% include open-new-window.html text='configuration file' url='https://kind.sigs.k8s.io/docs/user/quick-start/#creating-a-cluster' %}. Here you are providing kind configuration in order to disable simple networking implementation (default CNI) and change the pod ip CIDR.

```bash
cat > values.yaml <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
- role: worker
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
EOF
```

Start your Kind cluster with one master and two worker nodes using the following command.

```bash
kind create cluster --config kind.yaml --name dev
```

Confirm that you now have three nodes in your cluster with the following command.

```bash
kubectl get nodes -o wide
```

It should return something like the following.

```
NAME                STATUS   ROLES           AGE    VERSION   INTERNAL-IP   EXTERNAL-IP   OS-IMAGE             KERNEL-VERSION    CONTAINER-RUNTIME
dev-control-plane   Ready    control-plane   4m   v1.25.0   172.18.0.2    <none>        Ubuntu 22.04.1 LTS   5.10.0-17-amd64   containerd://1.6.7
dev-worker          Ready    <none>          4m   v1.25.0   172.18.0.4    <none>        Ubuntu 22.04.1 LTS   5.10.0-17-amd64   containerd://1.6.7
dev-worker2         Ready    <none>          4m   v1.25.0   172.18.0.3    <none>        Ubuntu 22.04.1 LTS   5.10.0-17-amd64   containerd://1.6.7
```


#### Install {{site.prodname}}
   {% tabs tab-group:grp1 %}
   <label:Operator,active:true>
   <%
Install the {{site.prodname}} operator and custom resource definitions.

```bash
kubectl create -f {{site.data.versions.first.manifests_url}}/manifests/tigera-operator.yaml
```

> **Note**: Due to the large size of the CRD bundle, `kubectl apply` might exceed request limits. Instead, use `kubectl create` or `kubectl replace`.
{: .alert .alert-info}

Install {{site.prodname}} by creating the necessary custom resource. For more information on configuration options available in this manifest, see [the installation reference]({{site.baseurl}}/reference/installation/api).

> **Note**: Before creating this manifest, read its contents and make sure its settings are correct for your environment. For example,
> if you have replaced `pod-network-cidr` you must change it in this file as well.
{: .alert .alert-info}

```bash
kubectl create -f {{site.data.versions.first.manifests_url}}/manifests/custom-resources.yaml
```
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

#### Verify {{site.prodname}} installation

You can verify {{site.prodname}} installation in your cluster by issuing the following command.

```bash
watch kubectl get pods -l k8s-app=calico-node -A
```

You should see a result similar to the below. Note that the namespace might be different, depending on the method you followed.

```
NAMESPACE     NAME                READY   STATUS    RESTARTS   AGE
kube-system   calico-node-2xcf4   1/1     Running   0          57s
kube-system   calico-node-gkqkg   1/1     Running   0          57s
kube-system   calico-node-j44hp   1/1     Running   0          57s

```

Use `ctrl+c` to break out of watch.

Congratulations you now have a Kind cluster equipped with {{site.prodname}}

#### Clean up

Issuing a delete command will destroy the cluster that you created in this tutorial.

```bash
kind delete cluster --name dev
```


### Next steps

**Required**
- [Install and configure calicoctl]({{site.basurl}}/maintenance/clis/calicoctl/install)

**Recommended tutorials**
- [Secure a simple application using the Kubernetes NetworkPolicy API]({{site.basurl}}/security/tutorials/kubernetes-policy-basic)
- [Control ingress and egress traffic using the Kubernetes NetworkPolicy API]({{site.basurl}}/security/tutorials/kubernetes-policy-advanced)
- [Run a tutorial that shows blocked and allowed connections in real time]({{site.basurl}}/security/tutorials/kubernetes-policy-demo/kubernetes-demo)
  
