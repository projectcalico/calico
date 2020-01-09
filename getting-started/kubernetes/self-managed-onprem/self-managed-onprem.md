---
title: Self-managed on-premises
---

### Big picture

Install the {{site.prodname}} open source product that includes both networking and network policy for self-managed on-premises deployments.

### Value

Designed to be used together, **{{site.prodname}} networking** and **network policy** are a powerful choice for a CaaS implementation. If you have the networking infrastructure and resources to manage Kubernetes on-premises, installing the full {{site.prodname}} product provides the most customization and control.

### Features

This how-to guide uses the following {{site.prodname}} features:

- **calico/node**
- **NetworkPolicy**
- **BGPConfiguration**
- **Typha**

### Concepts

#### {{site.prodname}} manifests

{{site.prodname}} provides manifests for easy customization. Each manifest contains the necessary resources for installing {{site.prodname}} on each node in your Kubernetes cluster. {{site.prodname}} installs the following Kubernetes resources:

- A `calico-node` pod on each host using a DaemonSet that:
  - Installs {{site.prodname}} CNI binaries and network config on each host using an init container
  - Runs the calico/node container
- `calico-etcd-secrets` secret, which optionally allows for providing etcd TLS assets
- `calico-config ConfigMap`, which contains parameters for configuring the install
- `calico-kube-controllers` deployment
- RBAC configuration for {{site.prodname}} services to access the Kubernetes API server
- If using Kubernetes as the datastore, custom resource definitions for the {{site.prodname}} data resources
- If installing more than 50 nodes, `calico-typha` for scaling deployments

#### Best practice: customize manifests prior to install

We recommend customizing [Calico manifests]({{site.url}}/reference/customize-manifests) before installing {{site.prodname}} on nodes; this avoids downstream manual updates to other {{site.prodname}} resources:

### Before you begin...

- Ensure that your Kubernetes cluster meets [Requirements]({site.url}}/getting-started/kubernetes/requirements)
  If you do not have a cluster,  see  [Using kubeadmin to create a cluster]({{site.url}}/getting-started-guides/kubeadm/)
- If you are using CoreOS, [make this required change to manifests]({{site.url}}/reference/faq#are-the-calico-manifests-compatible-with-coreos)

### How to 

The following steps install a {{site.prodname}} implementation with:

- {{site.prodname}} daemons and services running in the cluster
- {{site.prodname}} BGP networking infrastructure with full-mesh node-to-node peering, no encapsulation

#### Determine your datastore 

{{site.prodname}} supports both **Kubernetes API datastore (kdd)** and **etcd** datastores. The **Kubernetes API datastore** is preferred for on-premises deployments, but supports only Kubernetes workloads; **etcd** datastore is best for hybrid deployments. 

#### Install {{site.prodname}} on nodes

Choose one of the install links below, based on your datastore and number of nodes. 

>**Note**: If you choose, **Kubernetes API datastore - more than 50 nodes**, the {{site.prodname}} [Typha daemon](https://github.com/projectcalico/typha) is used for scaling. (Because etcd v3 already handles many clients, using Typha for etcd is redundant and not recommended.)
{: .alert .alert-info}

- [Install Calico with Kubernetes API datastore--50 nodes or less](#install-calico-with-kubernetes-api-datastore-50-nodes-or-less)
- [Install Calico with Kubernetes API datastore--more than 50 nodes](#install-calico-with-Kubernetes-api-datastore-more-than-50-nodes)
- [Install Calico with etcd datastore](#install-calico-with-etcd-datastore)

#### Install Calico with Kubernetes API datastore--50 nodes or less

1. Download the {{site.prodname}} networking manifest for the Kubernetes API datastore.

   ```
   curl {{ "/manifests/calico.yaml" | absolute_url }} -O
   ```
1. If you are using pod CIDR 192.168.0.0/16, skip this step. Otherwise, use the following commands to set the POD_CIDR environment variable containing your pod CIDR, and replace `192.168.0.0/16` in the manifest with your pod CIDR.

   ```
   POD_CIDR="<your-pod-cidr>" \
   sed -i -e "s?192.168.0.0/16?$POD_CIDR?g" calico.yaml
   ```
1. Customize the manifest if desired. 
1. Apply the manifest using the following command.

   ```
   kubectl apply -f calico.yaml
 
   ```

#### Install Calico with Kubernetes API datastore--more than 50 nodes

1. Download the {{site.prodname}} networking manifest for the Kubernetes API datastore.

   ```
   curl {{ "/manifests/calico.yaml" | absolute_url }} -O 
   ```
1. If you are using pod CIDR 10.244.0.0/16, skip this step. Otherwise, set the POD_CIDR environment variable with your pod CIDR, and replace `10.244.0.0/16` in the manifest with your pod CIDR.

   ```
   POD_CIDR="<your-pod-cidr>" \
   sed -i -e "s?10.244.0.0/16?$POD_CIDR?g" calico-typha.yaml
   ```
1. Modify the replica count in the Deployment named, `calico-typha` to the desired number of replicas.
   We recommend at least one replica for every 200 nodes, and no more than 20 replicas. In production, we recommend a minimum of three replicas to reduce the impact of rolling upgrades and failures. The number of replicas should always be less than the number of nodes, otherwise rolling upgrades will stall. In addition, Typha only helps with scale if there are fewer Typha instances than there are nodes.

> **Warning**: If you set `typha_service_name` without increasing the default replica count (0), Felix will try to connect to Typha and not find Typha instances, and will fail to start.
{: .alert .alert-danger}

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

1. Customize the manifest if desired.

1. Apply the manifest.

   ```
   kubectl apply -f calico-typha.yaml
   ```
#### Install Calico with etcd datastore

1. Download the {{site.prodname}} networking manifest for etcd.

   ```
   curl {{ "/manifests/calico.yaml" | absolute_url }} -O
   ```
1. If you are using pod CIDR 10.244.0.0/16, skip this step. Otherwise, set the POD_CIDR environment variable with your pod CIDR, and replace `10.244.0.0/16` in the manifest with your pod CIDR.

   ```
   POD_CIDR="<your-pod-cidr>" \
   sed -i -e "s?10.244.0.0/16?$POD_CIDR?g" calico-etcd.yaml
   ```
1. In the ConfigMap named, `calico-config`, set the value of etcd_endpoints to the IP address and port of your etcd server.

> **Tip**: You can specify more than one using commas as delimiters.
{: .alert .alert-info}

1. Customize the manifest if desired.
1. Apply the manifest using the following command.

   ```
   kubectl apply -f calico.yaml
   ```

### Next steps

**Tools**

- [Install and configure calicoctl]({{site.url}}/getting-started/calicoctl/install)

**Networking**

- If you are using the default BGP networking with full-mesh node-to-node peering with no encapsulation, go to [Configure BGP peering] to get traffic flowing between pods.
- If you are unsure about networking options, or want to implement encapsulation (overlay networking), see [Determine best networking option]().

**Security**

- [Secure Calico component communications]({{site.url}}/security/comms/crypto-auth)
- [Install Calico on hosts]({{site.url}}/getting-started/bare-metal/installation/)
  We highly recommend installing {{site.prodname}} on hosts to secure communications. But you may want to secure your pods with [Calico network policy]({{site.url}}/security/calico-network-policy) first, then come back and install {{site.prodname}} on hosts.
- If you are using {{site.prodname}} with Istio service mesh, get started here: [Enable application layer policy for Istio service mesh]({{site.url}}/security/enable-app-layer-policy)