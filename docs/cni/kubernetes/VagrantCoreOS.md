<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.13.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Deploying Calico and Kubernetes on CoreOS using Vagrant and VirtualBox

These instructions allow you to set up a Kubernetes v1.1.4 cluster with [Calico networking][calico-networking] using Vagrant and the [Calico CNI plugin][calico-cni]. This guide does not setup TLS between Kubernetes components.

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

Edit `calico-containers/docs/cni/cloud-config/node-config.yaml` and replace all instances of `kubernetes-master` with the IP address `172.18.18.101`. 

Edit `calico-containers/docs/cni/cloud-config/master-config.yaml` and remove the following line in `calico-node.service` to disable IP-in-IP, which is not needed for this guide.
```
ExecStartPre=/opt/bin/calicoctl pool add 192.168.0.0/16 --ipip --nat-outgoing
```

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

You should now have two CoreOS servers - one Kubernetes master and one Kubernetes node. The servers are named calico-01 and calico-02 
and have IP addresses 172.18.18.101 and 172.18.18.102.

At this point, it's worth checking that your servers can ping each other.

From calico-01

    ping 172.18.18.102

From calico-02

    ping 172.18.18.101

If you see ping failures, the likely culprit is a problem with the VirtualBox network between the VMs.  You should 
check that each host is connected to the same virtual network adapter in VirtualBox and rebooting the host may also 
help.  Remember to shut down the VMs with `vagrant halt` before you reboot.

You should also verify each host can access etcd.  The following will return an error if etcd is not available.

    curl -L http://172.18.18.101:2379/version

And finally check that Docker is running on both hosts by running

    docker ps
    
## 2. Using your cluster 
### 2.1 Deploying SkyDNS
You now have a basic Kubernetes cluster deployed using Calico networking.  Most Kubernetes deployments use SkyDNS for Kubernetes service discovery.  The following steps configure the SkyDNS service.

Log on to the master node.
```
vagrant ssh calico-01
```

Check that all your nodes have registered. You should see an entry for each node.
```
kubectl get nodes
```

Deploy the SkyDNS application using the provided Kubernetes manifest.
```
kubectl create -f skydns.yaml
```

Check that the DNS pod is running. It may take up to two minutes for the pod to start, after which the following command should show the `kube-dns-v9-xxxx` pod in `Running` state.
```
kubectl get pods --all-namespaces
```

>The output of the above command should resemble the following table.  Note the `Running` status:
```
NAMESPACE     NAME                READY     STATUS    RESTARTS   AGE
kube-system   kube-dns-v9-3o2rw   4/4       Running   0          2m
```

Check that the DNS pod has been networked using Calico.  You should see a single Calico endpoint. 
```
calicoctl endpoint show --detailed
```

### 2.2 Deploying the guestbook application.
You're now ready to deploy applications on your Cluster.  The following steps describe how to deploy the Kubernetes [guestbook application][guestbook].

Log on to the master node.
```
vagrant ssh calico-01
```

Create the guestbook application pods and services using the provided manifest.
```
kubectl create -f guestbook.yaml
```

Check that the redis-master, redis-slave, and frontend pods are running correctly.  After a few minutes, the following command should show all pods in `Running` state.
```
kubectl get pods
```
> Note: The guestbook demo relies on a number of docker images which may take up to 5 minutes to download.

Check that Calico endpoints have been created for the guestbook pods.
```
calicoctl endpoint show --detailed
```

The above manifests configure a web appliation that is exposed on port 30001 on each of your nodes using the Kubernetes NodePort mechanism. 
```
kubectl describe svc frontend
```
The service is available internally via a `10.100.0.X` IP address on port `80`, and outside the cluster using the NodePort `30001`.

To access the guestbook application frontend, visit `http://172.18.18.101:30001` in your favorite browser.  Because we used a NodePort service to expose it outside the cluster, it should also be available at `http://172.18.18.102:30001`.

[calico-networking]: https://github.com/projectcalico/calico-containers
[calico-cni]: https://github.com/projectcalico/calico-cni
[virtualbox]: https://www.virtualbox.org/
[vagrant]: https://www.vagrantup.com/downloads.html
[using-coreos]: http://coreos.com/docs/using-coreos/
[git]: http://git-scm.com/
[guestbook]: https://github.com/kubernetes/kubernetes/blob/master/examples/guestbook/README.md
[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/kubernetes/VagrantCoreOS.md?pixel)](https://github.com/igrigorik/ga-beacon)
