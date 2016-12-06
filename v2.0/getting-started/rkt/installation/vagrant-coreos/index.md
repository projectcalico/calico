---
title: Running the Calico rkt tutorials on CoreOS using Vagrant and VirtualBox
---

This tutorial describes how to set up a Calico cluster in a pure rkt environment.
rkt is used for running both the Calico components and the workloads.

## 1. Environment setup

This tutorial walks through getting a cluster set up with Vagrant.

### 1.1 Install dependencies

* [VirtualBox][virtualbox] 5.0.0 or greater.
* [Vagrant][vagrant] 1.8.5 or greater.
* [Git][git]

### 1.2 Clone this project

    git clone https://github.com/projectcalico/calico.git

### 1.3 Startup and SSH

Change into the directory for this guide:

    cd calico/{{page.version}}/getting-started/rkt/installation/vagrant-coreos

Run

    vagrant up

To connect to your servers

* Linux/Mac OS X
    * run `vagrant ssh <hostname>`
* Windows
    * Follow instructions from https://github.com/nickryand/vagrant-multi-putty
    * run `vagrant putty <hostname>`

### 1.4 Verify environment

You should now have two CoreOS servers. The servers are named calico-01 and calico-02
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

And finally check that `rkt` is running on both hosts by running

    sudo rkt list

## 2. Try out Calico Networking

Now that you have a basic two node CoreOS cluster setup, see the [Calico networking with rkt]({{site.baseurl}}/{{page.version}}/getting-started/rkt/tutorials/basic)

[virtualbox]: https://www.virtualbox.org/
[vagrant]: https://www.vagrantup.com/downloads.html
[git]: http://git-scm.com/
