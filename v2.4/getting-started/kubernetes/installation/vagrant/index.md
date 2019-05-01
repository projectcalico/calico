---
title: Deploying Calico and Kubernetes on Container Linux by CoreOS using Vagrant and VirtualBox
canonical_url: 'https://docs.projectcalico.org/v3.0/getting-started/kubernetes/installation/vagrant/index'
---

These instructions allow you to set up a Kubernetes cluster with Calico networking using Vagrant and the [Calico CNI plugin][cni-plugin]. This guide does not set up TLS between Kubernetes components.

## 1. Deploy cluster using Vagrant

### 1.1 Install dependencies

* [VirtualBox][virtualbox] 5.0.0 or greater.
* [Vagrant][vagrant] 1.7.4 or greater.
* [Curl][curl]

### 1.2 Download the source files

    curl -O {{site.url}}{{page.dir}}Vagrantfile
    curl -O {{site.url}}{{page.dir}}master-config.yaml
    curl -O {{site.url}}{{page.dir}}node-config.yaml

### 1.3 Startup and SSH

Run

    vagrant up

> *Note*: This will deploy a Kubernetes master and two Kubernetes nodes. To run more nodes, modify the value `num_instances` in the Vagrantfile before running `vagrant up`.

To connect to your servers

* Linux/Mac OS X
    * run `vagrant ssh <hostname>`
* Windows
    * Follow instructions from https://github.com/nickryand/vagrant-multi-putty
    * run `vagrant putty <hostname>`

### 1.4 Verify environment

You should now have three CoreOS Container Linux servers:

| Hostname    | IP            |
|-------------|---------------|
| k8s-master  | 172.18.18.101 |
| k8s-node-01 | 172.18.18.102 |
| k8s-node-02 | 172.18.18.103 |

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

If you see ping failures, the likely culprit is a problem with the VirtualBox network between the VMs. You should
check that each host is connected to the same virtual network adapter in VirtualBox and rebooting the host may also
help. Remember to shut down the VMs with `vagrant halt` before you reboot.

You should also verify each host can access etcd. The following will return an error if etcd is not available.

    curl -L http://172.18.18.101:2379/version

And finally check that Docker is running on both hosts by running

    docker ps

## 2. Configuring the Cluster and `kubectl`

Prequisite: [`kubectl` installed](https://kubernetes.io/docs/tasks/tools/install-kubectl/)

Let's configure `kubectl` so you can access the cluster from your local machine. 

```shell
kubectl config set-cluster vagrant-cluster --server=http://172.18.18.101:8080
kubectl config set-context vagrant-system --cluster=vagrant-cluster
kubectl config use-context vagrant-system
```

## 3. Install Addons

{% include {{page.version}}/install-k8s-addons.md %}

## Next Steps

You should now have a fully functioning Kubernetes cluster using Calico for networking. You're ready to use your cluster.

We recommend you try using [Calico for Kubernetes NetworkPolicy]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/tutorials/simple-policy).

[cni-plugin]: https://github.com/projectcalico/cni-plugin
[virtualbox]: https://www.virtualbox.org/
[vagrant]: https://www.vagrantup.com/downloads.html
[curl]: https://curl.haxx.se/
