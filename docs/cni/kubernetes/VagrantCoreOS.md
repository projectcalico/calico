<!--- master only -->
> ![warning](../../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Deploying Calico and Kubernetes on CoreOS using Vagrant and VirtualBox

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

## 2. Using your cluster
### 2.1 Enable NetworkPolicy API on the Cluster 
The Calico Policy Agent uses this API to enables network policy on Kubenrnetes.

To install it:

Log on to the master.
```
vagrant ssh k8s-master 
```

Install the manifest:
```
kubectl create -f policy.yaml
```

### 2.2 Deploying SkyDNS
You now have a basic Kubernetes cluster deployed using Calico networking.  Most Kubernetes deployments use SkyDNS for Kubernetes service discovery.  The following steps configure the SkyDNS service.

Log on to the master node.
```
vagrant ssh k8s-master 
```

Deploy the SkyDNS application using the provided Kubernetes manifest.
```
kubectl create -f skydns.yaml
```

Check that the DNS pod is running. It may take up to two minutes for the pod to start, after which the following command should show the `kube-dns-v9-xxxx` pod in `Running` state.
```
kubectl get pods --namespace=kube-system
```
> Note: The kube-dns-v9 pod is deployed in the `kube-system` namespace.  As such, we we must include the `--namespace=kube-system` option when using kubectl.

>The output of the above command should resemble the following table.  Note the `Running` status:
```
NAMESPACE     NAME                READY     STATUS    RESTARTS   AGE
kube-system   kube-dns-v9-3o2rw   4/4       Running   0          2m
```

Check that the DNS pod has been networked using Calico.  You should see a Calico endpoint created for the DNS pod.
```
calicoctl endpoint show --detailed
```

### 2.3 Next Steps
Try deploying an application to the cluster.
- [Calico Policy Demo](stars-demo/README.md)
- [Kubernetes guestbook](vagrant-coreos/guestbook.md)

You can also take a look at the various Kubernetes [example applications][examples].

[calico-networking]: https://github.com/projectcalico/calico-containers
[calico-cni]: https://github.com/projectcalico/calico-cni
[virtualbox]: https://www.virtualbox.org/
[vagrant]: https://www.vagrantup.com/downloads.html
[using-coreos]: http://coreos.com/docs/using-coreos/
[git]: http://git-scm.com/
[examples]: https://github.com/kubernetes/kubernetes/tree/master/examples

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/cni/kubernetes/VagrantCoreOS.md?pixel)](https://github.com/igrigorik/ga-beacon)
