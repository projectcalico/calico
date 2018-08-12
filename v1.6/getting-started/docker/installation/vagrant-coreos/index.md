---
title: Running the Calico tutorials on CoreOS using Vagrant and VirtualBox
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/docker/installation/vagrant-coreos/'
---

These instructions allow you to set up a CoreOS cluster ready to network Docker containers with
[Calico Docker networking][calico-networking] using Vagrant.

## 1. Streamlined setup of the VMs

### 1.1 Install dependencies

* [VirtualBox][virtualbox] 5.0.0 or greater.
* [Vagrant][vagrant] 1.7.4 or greater.
* [Git][git]

### 1.2 Clone this project

    git clone https://github.com/projectcalico/calico.git

### 1.4 Startup and SSH

Run the following:

    cd calico/{{page.version}}/getting-started/docker/installation/vagrant-coreos
    vagrant up

To connect to your servers

* Linux/Mac OS X
    * run `vagrant ssh <hostname>`
* Windows
    * Follow instructions from https://github.com/nickryand/vagrant-multi-putty
    * run `vagrant putty <hostname>`

### 1.5 Verify environment

You should now have two CoreOS servers, each running etcd in a cluster. The servers are named calico-01 and calico-02
and IP addresses 172.17.8.101 and 172.17.8.102.

At this point, it's worth checking that your servers can ping each other.

From calico-01

    ping 172.17.8.102

From calico-02

    ping 172.17.8.101

If you see ping failures, the likely culprit is a problem with the VirtualBox network between the VMs.  You should
check that each host is connected to the same virtual network adapter in VirtualBox and rebooting the host may also
help.  Remember to shut down the VMs with `vagrant halt` before you reboot.

You should also verify each host can access etcd.  The following will return an error if etcd is not available.

    curl -L http://$ETCD_AUTHORITY/version

And finally check that Docker is running on both hosts by running

    docker ps

## 2. Try out Calico networking

Now you have a basic two node CoreOS cluster setup, see the [Calico with Docker Networking Walkthrough]({{site.baseurl}}/{{page.version}}/getting-started/docker/tutorials/basic) for information on how to try Calico Networking.

[calico-networking]: https://github.com/projectcalico/calico-containers
[virtualbox]: https://www.virtualbox.org/
[vagrant]: https://www.vagrantup.com/downloads.html
[using-coreos]: http://coreos.com/using-coreos/
[git]: http://git-scm.com/
