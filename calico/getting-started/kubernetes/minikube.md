---
title: Quickstart for Calico on minikube
description: Enable Calico on a single/multi-node minikube cluster for testing or development in under 1 minute.
canonical_url: '/getting-started/kubernetes/minikube'
---

### Big picture

This quickstart gets you a single-node minikube cluster with {{site.prodname}}
in approximately 1 minute. You can use this cluster for testing and
development.

### Value

Use this quickstart to quickly and easily try {{site.prodname}} features.

### Before you begin

- Install, but do not start, minikube. {% include open-new-window.html text='How to install minikube' url='https://minikube.sigs.k8s.io/docs/start/#what-youll-need' %}
- Install kubectl.{% include open-new-window.html text='How to install kubectl' url='https://kubernetes.io/docs/tasks/tools/install-kubectl/' %}
- Install a minikube driver. For example Docker. A full List of available drivers can be {% include open-new-window.html  text='found here.' url='https://minikube.sigs.k8s.io/docs/drivers/' %}

### How to

#### Create a single-node minikube cluster

{% tabs %}
<label:Built-in {{site.prodname}},active:true>
<%

Minikube offers a built-in {{site.prodname}} implementation, this is a quick way to checkout {{site.prodname}} features.

> **Note**: Enabling preinstalled {{site.prodname}} might be the quickest way for testing. However, if you like to checkout a more recent version or features of {{site.prodname}} you should consider using Manifest or Operator approach.
{: .alert .alert-info}

```bash
minikube start --network-plugin=cni --cni=calico
```

%>
<label:Operator>
<%

Start your minikube cluster with one master node using the following command.

> **Note**: If `192.168.0.0/16` is already in use within your network you must select a different pod network CIDR, by replacing `192.168.0.0/16` in the following command.
{: .alert .alert-info}

```bash
minikube start --network-plugin=cni --extra-config=kubeadm.pod-network-cidr=192.168.0.0/16
```

Install the Tigera {{site.prodname}} operator and custom resource definitions.

```bash
kubectl create -f {{site.data.versions.first.manifests_url}}/manifests/tigera-operator.yaml
```

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

Start your minikube cluster with one master node using the following command.

```bash
minikube start --network-plugin=cni 
```

Install {{site.prodname}}.

```bash
kubectl apply -f {{site.data.versions.first.manifests_url}}/manifests/calico.yaml
```

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
kube-system   calico-node-mlqvs   1/1     Running   0          5m18s
```

Use `ctrl+c` to break out of watch.

Congratulations you now have a minikube cluster equipped with {{site.prodname}}

#### Add an additional worker node

> **Note**: This as an optional step, you can safely skip this step if you do not require an additional worker node.
{: .alert .alert-info}

```bash
minikube node add
```

Verify nodes using the following command

```bash
kubectl get nodes
```
#### Clean up

Issuing a delete command will destroy the cluster that you created in this tutorial.

```bash
minikube delete
```


### Next steps

**Required**
- [Install and configure calicoctl]({{site.basurl}}/maintenance/clis/calicoctl/install)

**Recommended tutorials**
- [Secure a simple application using the Kubernetes NetworkPolicy API]({{site.basurl}}/security/tutorials/kubernetes-policy-basic)
- [Control ingress and egress traffic using the Kubernetes NetworkPolicy API]({{site.basurl}}/security/tutorials/kubernetes-policy-advanced)
- [Run a tutorial that shows blocked and allowed connections in real time]({{site.basurl}}/security/tutorials/kubernetes-policy-demo/kubernetes-demo)
  
