<!--- master only -->
> ![warning](../../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.22.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Deploying Calico and Kubernetes on GCE

These instructions allow you to set up a Kubernetes cluster with Calico networking on GCE using the [Calico CNI plugin][calico-cni]. This guide does not setup TLS between Kubernetes components or on the Kubernetes API.

## 1. Getting started with GCE
These instructions describe how to set up two CoreOS hosts on GCE.  For more general background, see
[the CoreOS on GCE documentation][coreos-gce].

### 1.1 Install the gcloud tool
If you already have the `gcloud` utility installed, and a GCE project configured, you may skip this step.

Download and install GCE, then restart your terminal:
```
curl https://sdk.cloud.google.com | bash
```
For more information, see Google's [gcloud install instructions][gcloud-instructions].

Log into your account:
```
gcloud auth login
```

In the GCE web console, create a project and enable the Compute Engine API.
Set the project as the default for gcloud:
```
gcloud config set project PROJECT_ID
```
And set a default zone
```
gcloud config set compute/zone us-central1-a
```

### 1.2 Setting up GCE networking
GCE blocks traffic between hosts by default; run the following command to allow Calico traffic to flow between
containers on different hosts (where the source-ranges parameter assumes you have created your project with the
default GCE network parameters - modify the address range if yours is different):
```
gcloud compute firewall-rules create calico-ipip --allow 4 --network "default" --source-ranges "10.128.0.0/9"
```
You can verify the rule with this command:
```
gcloud compute firewall-rules list
```

<!--- master only -->
### 1.3 Clone this project

    git clone https://github.com/projectcalico/calico-containers.git
<!--- else
### 1.3 Clone this project, and checkout the **release** release

    git clone https://github.com/projectcalico/calico-containers.git
    git checkout tags/**release**
<!--- end of master only -->

## 2. Deploy the VMs
Change into the directory for this guide.
```
cd calico-containers/docs/cni/kubernetes/
```

Deploy the Kubernetes master node using the following command:
```
gcloud compute instances create \
  kubernetes-master \
  --image-project coreos-cloud \
  --image coreos-stable-1010-6-0-v20160628 \
  --machine-type n1-standard-1 \
  --metadata-from-file user-data=cloud-config/master-config.yaml
```

Deploy at least one worker node using the following command:
```
gcloud compute instances create \
  kubernetes-node-1 \
  --image-project coreos-cloud \
  --image coreos-stable-1010-6-0-v20160628 \
  --machine-type n1-standard-1 \
  --metadata-from-file user-data=cloud-config/node-config.yaml
```

You should have SSH access to your machines using the following command:
```
gcloud compute ssh <INSTANCE NAME>
```

## Configure the Cluster
### 3.1 Configure Outbound NAT and IP-in-IP 

To enable connectivity to the internet for our Pods, we'll use `calicoctl`:

```
# Log into the master instance.
gcloud compute ssh kubernetes-master

# Enable outgoing NAT and ipip on the Calico pool.
docker run --rm --net=host calico/ctl pool add 192.168.0.0/16 --ipip --nat-outgoing
```

### 3.2 Configure kubectl
The following steps configure remote kubectl access to your cluster.

Download `kubectl`
```
sudo wget -O /usr/local/bin/kubectl https://storage.googleapis.com/kubernetes-release/release/v1.3.5/bin/linux/amd64/kubectl
sudo chmod +x /usr/local/bin/kubectl
```

The following command sets up SSH forwarding of port 8080 to your master node so that you can run `kubectl` commands on your local machine.
```
gcloud compute ssh kubernetes-master --quiet --ssh-flag="-nNT" --ssh-flag="-L 8080:localhost:8080" &
```

Verify that you can access the Kubernetes API.  The following command should return a list of Kubernetes nodes.
```
kubectl get nodes
```

>If successful, the above command should output something like this:
```
NAME          STATUS                     AGE
10.240.0.25   Ready,SchedulingDisabled   6m
10.240.0.26   Ready                      6m
```

### 3.3 Next Steps
Now that you have a cluster with `kubectl` configured, you can [install Calico and other cluster addons](InstallAddons.md).

[calico-cni]: https://github.com/projectcalico/calico-cni
[coreos-gce]: https://coreos.com/docs/running-coreos/cloud-providers/google-compute-engine/
[gcloud-instructions]: https://cloud.google.com/compute/docs/gcloud-compute/


[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/cni/kubernetes/GCE.md?pixel)](https://github.com/igrigorik/ga-beacon)
