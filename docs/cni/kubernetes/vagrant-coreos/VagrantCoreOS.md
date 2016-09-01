<!--- master only -->
> ![warning](../../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.22.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Deploying Kubernetes on CoreOS using Vagrant and VirtualBox

These instructions allow you to set up a Kubernetes cluster with [Calico networking][calico-networking] using Vagrant and the [Calico CNI plugin][calico-cni]. This guide does not setup TLS between Kubernetes components.

## 1. Deploy cluster using Vagrant

### 1.1 Install dependencies

* [VirtualBox][virtualbox] 5.0.0 or greater.
* [Vagrant][vagrant] 1.7.4 or greater.
* [Git][git]

<!--- master only -->
### 1.2 Clone this project

    git clone https://github.com/projectcalico/calico-containers.git
<!--- else
### 1.2 Clone this project, and checkout the **release** release

    git clone https://github.com/projectcalico/calico-containers.git
    git checkout tags/**release**
<!--- end of master only -->

### 1.3 Startup and SSH

Change into the directory for this guide:

    cd calico-containers/docs/cni/kubernetes/vagrant-coreos

Run

    vagrant up

> *Note*: This will deploy a Kubernetes master and a single Kubernetes node.  To run more nodes, modify the value `num_instances` in the Vagrantfile before running `vagrant up`.

To connect to your servers
* Linux/Mac OS X
    * run `vagrant ssh <hostname>`
* Windows
    * Follow instructions from https://github.com/nickryand/vagrant-multi-putty
    * run `vagrant putty <hostname>`

### 1.4 Verify environment

You should now have three CoreOS servers - one Kubernetes master and two Kubernetes nodes. The servers are named k8s-master, k8s-node-01, and k8s-node-02 
and have IP addresses 172.18.18.101, 172.18.18.102, and 172.18.18.103.

At this point, it's worth checking that your servers can ping each other.

From k8s-master 

    ping 172.18.18.102
    ping 172.18.18.103

From k8s-node-01

    ping 172.18.18.101
    ping 172.18.18.103

From k8s-node-02

    ping 172.18.18.101
    ping 172.18.18.102

If you see ping failures, the likely culprit is a problem with the VirtualBox network between the VMs.  You should
check that each host is connected to the same virtual network adapter in VirtualBox and rebooting the host may also
help.  Remember to shut down the VMs with `vagrant halt` before you reboot.

You should also verify each host can access etcd.  The following will return an error if etcd is not available.

    curl -L http://172.18.18.101:2379/version

And finally check that Docker is running on both hosts by running

    docker ps

## 2. Configuring the Cluster 
### 2.1 Configure `kubectl`
Let's configure `kubectl` so you can access the cluster from your local machine. Make sure you have `kubectl` installed locally.  The version you choose depends on your host OS.

For Mac:
```
wget http://storage.googleapis.com/kubernetes-release/release/v1.4.0-alpha.3/bin/darwin/amd64/kubectl
chmod +x ./kubectl
```

For Linux:
```
wget http://storage.googleapis.com/kubernetes-release/release/v1.4.0-alpha.3/bin/linux/amd64/kubectl
chmod +x ./kubectl
```

Then, tell `kubectl` to use the Vagrant cluster we just created.
```
kubectl config set-cluster vagrant-cluster --server=http://172.18.18.101:8080
kubectl config set-context vagrant-system --cluster=vagrant-cluster
kubectl config use-context vagrant-system
```

## 3. Next Steps
Now that you have a cluster with `kubectl` configured, you can [install Calico and other cluster addons](../InstallAddons.md).

[calico-networking]: https://github.com/projectcalico/calico-containers
[calico-cni]: https://github.com/projectcalico/calico-cni
[virtualbox]: https://www.virtualbox.org/
[vagrant]: https://www.vagrantup.com/downloads.html
[git]: http://git-scm.com/

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/cni/kubernetes/VagrantCoreOS.md?pixel)](https://github.com/igrigorik/ga-beacon)
