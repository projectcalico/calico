---
title: Manually install Calico
canonical_url: 'https://docs.projectcalico.org/v3.9/getting-started/kubernetes/installation/flannel'
---

### Big picture

Manually install the Calico open source product that includes both networking and network policy.

### Value

Designed to be used together, Calico networking and network policy are a powerful choice for a CaaS implementation. If you have the networking infrastructure and resources to self-manage Kubernetes, manually installing Calico allows for most customization and control. Because manual installation requires customization, more planning is required before installing Calico on nodes.  For quicker or simpler installation, see [Quickstart]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes).

### Concepts

#### Calico manifests

Calico provides manifests for easy customization. Each manifest contains the necessary resources for installing Calico on each node in your Kubernetes cluster. Calico installs the following Kubernetes resources:

- The `calico/node` container on each host using a DaemonSet
- Calico CNI binaries and network config on each host using a DaemonSet
- `calico-etcd-secrets` secret, which optionally allows for providing etcd TLS assets
- `calico-config` ConfigMap, which contains parameters for configuring the install
and runs calico/kube-controllers as a deployment.

We recommend customizing the manifests before installing Calico; this avoids manual updates to other Calico resources later. 

## Before you begin

- Ensure that your Kubernetes cluster meets the [Calico system requirements]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/requirements)
- If you are using CoreOS, [make this required change]()

How to...

1. [Determine the best Calico networking option]()
1. [Determine your datastore]()
1. [Customize your manifests]() 
1. [Install Calico on nodes]()

#### Determine the best Calico networking option

If you have a choice, using Calico without encapsulation is preferred, and is the default. However, if you need overlay networking (IP in IP or VXLAN), see [Determine your best networking option]({{site.baseurl}}/{{page.version}}/networking/determine-best-networking).

#### Determine your datastore

For self-managed Kubernetes, Calico supports both Kubernetes API datastore (kdd) and etcd datastores. The Kubernetes API datastore is the preferred datastore for on-premises deployments, but supports only Kubernetes workloads; etcd datastore is best for hybrid deployments. 

#### Customize your manifests

A best practice is to customize the following Calico manifests before installing Calico on nodes; this avoids downstream manual updates to other Calico resources:

[Customize Calico manifests]({{site.baseurl}}/{{page.version}}/reference/customize-manifests)
[Configure calico/node]({{site.baseurl}}/{{page.version}}/reference/node/configuration)
[Configure Calico CNI plugins]({{site.baseurl}}/{{page.version}}/reference/cni-plugin/configuration)
[Configure Calico Kubernetes controllers]({{site.baseurl}}/{{page.version}}/reference/kube-controllers/configuration#the-calicokube-controllers-container)

#### Install Calico on nodes

The Calico install for kdd provides a scaling option for clusters with more than 50 nodes. Calico uses the [Typha daemon](https://github.com/projectcalico/typha) for scaling; although Typha can be used with etcd, etcd v3 already handles many clients so it is redundant and not recommended.

- Install with Kubernetes API datastore--50 nodes or less
- Install with Kubernetes API datastore--more than 50 nodes
- Install with etcd datastore

##### Install with Kubernetes API datastore--50 nodes or less

Download the Calico networking manifest for the Kubernetes API datastore.

```
curl https://docs.projectcalico.org/v3.9/manifests/calico.yaml -O
```
If you are using pod CIDR 192.168.0.0/16, skip to the next step. If you are using a different pod CIDR, use the following commands to set an environment variable called POD_CIDR containing your pod CIDR and replace 192.168.0.0/16 in the manifest with your pod CIDR.

```
POD_CIDR="<your-pod-cidr>" \
sed -i -e "s?192.168.0.0/16?$POD_CIDR?g" calico.yaml
```
Apply the manifest using the following command.

```
kubectl apply -f calico.yaml
```
##### Install with Kubernetes API datastore--more than 50 nodes

Download the Calico networking manifest for the Kubernetes API datastore.

```
curl https://docs.projectcalico.org/v3.9/manifests/calico-typha.yaml -o calico.yaml
```
If you are using pod CIDR 10.244.0.0/16, skip to the next step. If you are using a different pod CIDR, use the following commands to set an environment variable called POD_CIDR containing your pod CIDR and replace 10.244.0.0/16 in the manifest with your pod CIDR.

```
POD_CIDR="<your-pod-cidr>" \
sed -i -e "s?10.244.0.0/16?$POD_CIDR?g" calico-typha.yaml
```
Modify the replica count in the Deployment named, calico-typha to the desired number of replicas.
We recommend at least one replica for every 200 nodes and no more than 20 replicas. In production, we recommend a minimum of three replicas to reduce the impact of rolling upgrades and failures. The number of replicas should always be less than the number of nodes, otherwise rolling upgrades will stall. In addition, Typha only helps with scale if there are fewer Typha instances than there are nodes.

```
apiVersion: apps/v1beta1
          kind: Deployment
          metadata:
            name: calico-typha
  ...
spec:
  ...
  replicas: <number of replicas>
```

>**Warning**: If you set typha_service_name without increasing the replica count from its default of 0 Felix will try to connect to Typha, find no Typha instances to connect to, and fail to start.


Apply the manifest.
```
kubectl apply -f calico-typha.yaml
```
Install with etcd
Download the Calico networking manifest for etcd.

```
curl https://docs.projectcalico.org/v3.9/manifests/calico-etcd.yaml -o calico.yaml
```
If you are using pod CIDR 10.244.0.0/16, skip to the next step. If you are using a different pod CIDR, use the following commands to set an environment variable called POD_CIDR containing your pod CIDR and replace 10.244.0.0/16 in the manifest with your pod CIDR.

```
POD_CIDR="<your-pod-cidr>" \
sed -i -e "s?10.244.0.0/16?$POD_CIDR?g" calico-etcd.yaml
```
In the ConfigMap named calico-config, set the value of etcd_endpoints to the IP address and port of your etcd server.
Tip: You can specify more than one using commas as delimiters.


Apply the manifest using the following command.

```
kubectl apply -f calico-etcd.yaml
```

### Above and beyond

If you are implementing Calico with Istio, you can now add the required [Enable application layer policy]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/app-layer-policy).
