---
title: Self-managed Kubernetes in Google Compute Engine (GCE)
description: Use Calico with a self-managed Kubernetes cluster in Google Compute Engine (GCE).
---

### Big picture

Use {{site.prodname}} with a self-managed Kubernetes cluster in Google Compute Engine (GCE). 

### Value

Managing your own Kubernetes cluster (as opposed to using a managed-Kubernetes service like GKE) gives you the most flexibility in configuring {{site.prodname}} and Kubernetes. {{site.prodname}} combines flexible networking capabilities with "run-anywhere" security enforcement to provide a solution with native Linux kernel performance and true cloud-native scalability.

### Concepts

**kubeadm** is a cluster management tool that is used to install Kubernetes.

### Before you begin...

{% include open-new-window.html text='Install and configure the Google Cloud CLI tools' url='https://cloud.google.com/sdk/docs/quickstarts' %}

### How to

There are many ways to install and manage Kubernetes in GCE. Using kubeadm is a good default choice for most people, as it gives you access to all of {{site.prodname}}’s [flexible and powerful networking features]({{site.baseurl}}/networking). However, there are other options that may work better for your environment.

- [kubeadm for Calico networking and network policy](#kubeadm-for-calico-networking-and-network-policy)
- [Other tools and options](#other-tools-and-options)

#### kubeadm for Calico networking and network policy

##### Create cloud resources

You will need at least one VM to serve as a control plane node and one or more worker nodes. (It is possible to have control plane nodes also act as workers. This is not recommended in most cases and not covered by this guide.)  See [requirements]({{site.baseurl}}/getting-started/kubernetes/requirements) for specific OS requirements for these VMs.

The following worked example creates a single control node and three workers on a dedicated virtual private network (VPC). Adjust the example as needed for your requirements. Consider a dedicated infrastructure management tool like {% include open-new-window.html text='Terraform' url='https://www.terraform.io/' %} for managing cloud resources. (This example is adapted from {% include open-new-window.html text='Kubernetes the Hard Way' url='https://github.com/kelseyhightower/kubernetes-the-hard-way/blob/master/docs/03-compute-resources.md' %}.)

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

Install `kubeadm`,` kubelet`, and `kubectl` on each node (see {% include open-new-window.html text='kubeadm docs' url='https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/#installing-kubeadm-kubelet-and-kubectl' %} for more details).

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

On the controller, install {{site.prodname}} using the operator:

```
kubectl create -f {{ "/manifests/tigera-operator.yaml" | absolute_url }}
```

Downlaod the custom resources necessary to configure {{site.prodname}}

```
curl {{ "/manifests/custom-resources.yaml" | absolute_url}} -O
```

If you wish to customize the {{site.prodname}} install, customize the downloaded custom-resources.yaml manifest.  Then create the manifest to install {{site.prodname}}.

```
kubectl create -f custom-resources.yaml
```

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:IPIP,Routing:BGP,Datastore:Kubernetes' %}   

#### Other tools and options

##### Terraform

You may have noticed that the bulk of the above instructions are about provisioning the Google Cloud resources for the cluster and installing Kubernetes. Terraform is a tool for automating infrastructure provisioning using declarative configurations.  You can also go as far as automating the install of Docker, kubeadm, and Kubernetes using Terraform “provisioners.” See the {% include open-new-window.html text='Terraform documentation' url='https://www.terraform.io/docs/index.html' %} for more details.

##### Kubespray

{% include open-new-window.html text='Kubespray' url='https://kubespray.io/' %} is a tool for provisioning and managing Kubernetes clusters with support for multiple clouds including Google Compute Engine.  Calico is the default networking provider, or you can set the `kube_network_plugin` variable to `calico`. See the Kubespray docs for more details. See the {% include open-new-window.html text='Kubespray docs' url='https://kubespray.io/#/?id=network-plugins' %} for more details.

### Next steps

**Required**
- [Install and configure calicoctl]({{site.baseurl}}/maintenance/clis/calicoctl/install)

**Recommended**
- {% include open-new-window.html text='Video: Everything you need to know about Kubernetes networking on Google cloud' url='https://www.projectcalico.org/everything-you-need-to-know-about-kubernetes-networking-on-google-cloud/' %} 
- [Try out {{site.prodname}} network policy]({{site.baseurl}}/security/calico-network-policy)
