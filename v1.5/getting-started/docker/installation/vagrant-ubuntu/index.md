---
title: Running the Calico tutorials on Ubuntu using Vagrant and VirtualBox
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/docker/installation/vagrant-ubuntu/'
---

These instructions allow you to set up an Ubuntu cluster ready to network Docker containers with
[Calico Docker networking][calico-networking] using Vagrant.

## 1. Streamlined setup of the VMs

### 1.1 Install dependencies

* [VirtualBox][virtualbox] 5.0.22 or greater.
* [Vagrant][vagrant] 1.8.4 or greater.
* [Git][git]

### 1.2 Clone this project

    git clone https://github.com/projectcalico/calico.git

### 1.3 Startup and SSH

For Calico as a Docker network plugin

    cd calico/{{page.version}}/getting-started/docker/installation/vagrant-ubuntu
    vagrant up

To connect to your servers

* Linux/Mac OS X
    * run `vagrant ssh <hostname>`
* Windows
    * Follow instructions from https://github.com/nickryand/vagrant-multi-putty
    * run `vagrant putty <hostname>`

### 1.4 Verify environment

You should now have two Ubuntu servers, with Etcd running on the first server.

At this point, it's worth checking that your servers can ping each other.

From calico-1

    ping 172.17.8.102

From calico-2

    ping 172.17.8.101

If you see ping failures, the likely culprit is a problem with the VirtualBox network between the VMs.  You should
check that each host is connected to the same virtual network adapter in VirtualBox and rebooting the host may also
help.  Remember to shut down the VMs with `vagrant halt` before you reboot.

You should also verify each host can access etcd.  The following will return an error if etcd is not available.

    curl -L http://$ETCD_AUTHORITY/version

And finally check that Docker is running on both hosts by running

    docker ps

## 2. Try out Calico Networking

Now that you have a basic two node Ubuntu cluster setup, see the [Calico as a Docker network plugin walkthrough]({{site.baseurl}}/{{page.version}}/getting-started/docker/tutorials/basic)

[libnetwork]: https://github.com/docker/libnetwork
[experimental-channel]: https://github.com/docker/docker/tree/master/experimental
[virtualbox]: https://www.virtualbox.org/
[vagrant]: https://www.vagrantup.com/downloads.html
[git]: http://git-scm.com/
[calico-networking]: https://github.com/projectcalico/calico-containers
