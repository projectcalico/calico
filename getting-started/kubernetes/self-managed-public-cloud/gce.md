---
title: Self-managed Kubernetes in Google Compute Engine (GCE)
description: Use Calico with a self-managed Kubernetes cluster in Google Compute Engine (GCE)
---

### Big picture

Use {{site.prodname}} with a self-managed Kubernetes cluster in Google Compute Engine (GCE). 

### Value

Managing your own Kubernetes cluster (as opposed to using a managed-Kubernetes service like GKE) gives you the most flexibility in configuring {{site.prodname}} and Kubernetes. {{site.prodname}} provides both **networking** and **network security** for containers, virtual machines, and native host-based workloads across a broad range of platforms including Kubernetes, OpenShift, Docker EE, OpenStack, and bare metal services. {{site.prodname}} combines flexible networking capabilities with "run-anywhere" security enforcement to provide a solution with native Linux kernel performance and true cloud-native scalability.

### Concepts

**kubeadm** is a cluster management tool that is used to install Kubernetes.

### Before you begin...

[Install and configure the Google Cloud CLI tools](https://cloud.google.com/sdk/docs/quickstarts)

### How to

There are many ways to install and manage Kubernetes in AWS. Using kubeadm is a good default choice for most people, as it gives you access to all of {{site.prodname}}’s [flexible and powerful networking features]({{site.baseurl}}/networking). However, there are other options that may work better for your environment.

- [kubeadm for Calico networking and network policy](#kubeadm-for-calico-networking-and-network-policy)
- [Other tools and options](#other-tools-and-options)

#### kubeadm for Calico networking and network policy

##### Create cloud resources

You will need at least one VM to serve as a control plane node and one or more worker nodes. (It is possible to have control plane nodes also act as workers. This is not recommended in most cases and not covered by this guide.)  See [requirements]({{site.baseurl}}/getting-started/kubernetes/requirements) for specific OS requirements for these VMs.

The following worked example creates a single control node and three workers on a dedicated virtual private network (VPC). Adjust the example as needed for your requirements. Consider a dedicated infrastructure management tool like [Terraform](https://docs.google.com/document/d/1-Vm8tdxc9GJ4JVXwVrHqQv96jU1eeadQeZyCDdU2bV4/edit#heading=h.876rtqebbyno) for managing cloud resources. (This example is adapted from [Kubernetes the Hard Way](https://github.com/kelseyhightower/kubernetes-the-hard-way/blob/master/docs/03-compute-resources.md).)

**Create the VPC**

```
gcloud compute networks create example-k8s --subnet-mode custom
```

Create the k8s-nodes subnet in the example-k8s VPC network:

```
gcloud compute networks subnets create k8s-nodes \
  --network example-k8s \
  --range 10.240.0.0/24
```
Create a firewall rule that allows internal communication across TCP, UDP, ICMP and IP in IP (used for the Calico overlay):

```
gcloud compute firewall-rules create example-k8s-allow-internal \
  --allow tcp,udp,icmp,ipip \
  --network example-k8s \
  --source-ranges 10.240.0.0/24
```

Create a firewall rule that allows external SSH, ICMP, and HTTPS:

```
gcloud compute firewall-rules create example-k8s-allow-external \
  --allow tcp:22,tcp:6443,icmp \
  --network example-k8s \
  --source-ranges 0.0.0.0/0
```

Create the controller VM:

```
gcloud compute instances create controller \
    --async \
    --boot-disk-size 200GB \
    --can-ip-forward \
    --image-family ubuntu-1804-lts \
    --image-project ubuntu-os-cloud \
    --machine-type n1-standard-2 \
    --private-network-ip 10.240.0.11 \
    --scopes compute-rw,storage-ro,service-management,service-control,logging-write,monitoring \
    --subnet k8s-nodes \
    --zone us-central1-f \
    --tags example-k8s,controller
```

**Create three worker VMs**

```
for i in 0 1 2; do
  gcloud compute instances create worker-${i} \
    --async \
    --boot-disk-size 200GB \
    --can-ip-forward \
    --image-family ubuntu-1804-lts \
    --image-project ubuntu-os-cloud \
    --machine-type n1-standard-2 \
    --private-network-ip 10.240.0.2${i} \
    --scopes compute-rw,storage-ro,service-management,service-control,logging-write,monitoring \
    --subnet k8s-nodes \
    --zone us-central1-f \
    --tags example-k8s,worker
done
```

Install Docker on the controller VM and each worker VM.  On each VM run:

```
sudo apt update
sudo apt install -y docker.io 
sudo systemctl enable docker.service
sudo apt install -y apt-transport-https curl
```

##### Install Kubernetes and create the cluster

Install `kubeadm`,` kubelet`, and `kubectl` on each node (see [kubeadm docs](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/#installing-kubeadm-kubelet-and-kubectl) for more details).

```
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
cat <<EOF | sudo tee /etc/apt/sources.list.d/kubernetes.list
deb https://apt.kubernetes.io/ kubernetes-xenial main
EOF
sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl
```

Create the controller node of a new cluster. On the controller VM, execute:

```
sudo kubeadm init --pod-network-cidr 192.168.0.0/16
```

To set up kubectl for the ubuntu user, run:

```
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```
The final line of the kubeadm init output contains the command for joining your workers to the controller.  Run this on each worker, prepending `sudo` to run it as root.  It will look something like this:

```
sudo kubeadm join 10.240.0.11:6443 --token <token> --discovery-token-ca-cert-hash sha256:<hash>
```

On the controller, verify that all nodes have joined

```
kubectl get nodes
```
which should output something similar to:

```
NAME         STATUS     ROLES    AGE     VERSION
controller   NotReady   master   5m49s   v1.17.2
worker-0     NotReady   <none>   3m38s   v1.17.2
worker-1     NotReady   <none>   3m7s    v1.17.2
worker-2     NotReady   <none>   5s      v1.17.2
```

##### Install {{site.prodname}}

On the controller, install {{site.prodname}} from the manifest:

```
curl https://docs.projectcalico.org/master/manifests/calico.yaml -O
```

If you wish to customize the {{site.prodname}} install, customize the downloaded calico.yaml manifest.  Then apply the manifest to install {{site.prodname}}.

```
kubectl apply -f calico.yaml
```

#### Other tools and options

##### Amazon VPI CNI plugin

An alternative to using {{site.prodname}} for both networking and network policy, is to use the Amazon’s VPC CNI plugin for networking and {{site.prodname}} for network policy. The advantage of this approach is that pods are assigned IP addresses associated with Elastic Network Interfaces on worker nodes. The IPs come from the VPC network pool and therefore do not require NAT to access resources outside the Kubernetes cluster.

Set your kops cluster configuration to:

```
networking:
  amazonvpc: {}
```
Then install {{site.prodname}} for network policy only after the cluster is up and ready.

##### Kubespray

[Kubespray](https://kubespray.io/) is a tool for provisioning and managing Kubernetes clusters with support for multiple clouds including Amazon Web Services. {{site.prodname}} is the default networking provider, providing both networking and network policy. You can explicitly set the `kube_network_plugin` variable to `calico`, or not (given it is the default). See the [Kubespray docs](https://kubespray.io/#/?id=network-plugins) for more details.

### Above and beyond

- [Install and configure calicoctl]({{site.baseurl}}/getting-started/calicoctl/install)
- [Try out {{site.prodname}} network policy]({{site.baseurl}}/security/calico-network-policy)