---
title: Running the Calico tutorials on CoreOS Container Linux using Vagrant and VirtualBox
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/docker/installation/vagrant-coreos/index'
---

These instructions allow you to set up a CoreOS Container Linux cluster ready to network Docker containers with
Calico networking using Vagrant.

## 1. Streamlined setup of the VMs

### 1.1 Install dependencies

* [VirtualBox][virtualbox] 5.1.8 or greater.
* [Vagrant][vagrant] 1.8.5 or greater.
* [Curl][curl]

### 1.2 Download the source files

    mkdir demo; cd demo
    curl -O {{site.url}}{{page.dir}}Vagrantfile
    curl -O {{site.url}}{{page.dir }}user-data-first
    curl -O {{site.url}}{{page.dir }}user-data-others

### 1.4 Startup and SSH

Run the following:

    vagrant up

To connect to your servers

* Linux/Mac OS X
    * run `vagrant ssh <hostname>`
* Windows
    * Follow instructions from https://github.com/nickryand/vagrant-multi-putty
    * run `vagrant putty <hostname>`

### 1.5 Verify environment

You should now have two CoreOS Container Linux servers, each running etcd in a cluster. The servers are named calico-01 and calico-02
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

    curl -L http://172.17.8.101:2379/version

And finally check that Docker is running on both hosts by running

    docker ps

## 2. Install Calico

With your VMs running, and connectivity between them established,
it is time to launch `calico/node`.

The Vagrant machines already have `calicoctl` installed. Use it to launch `calico/node`:

    sudo ETCD_ENDPOINTS=http://172.17.8.101:2379 calicoctl node run --node-image=quay.io/calico/node:{{site.data.versions[page.version].first.title}}

Append the `--use-docker-networking-container-labels` flag to the `calicoctl node run` command if you're combining
[Docker Labels and Calico Policy]({{site.baseurl}}/{{page.version}}/getting-started/docker/tutorials/security-using-docker-labels-and-calico-policy).

Check that the `calico/node` container is running on this host:

    docker ps

You should see output like this on each node

    vagrant@calico-01:~$ docker ps
    CONTAINER ID        IMAGE                        COMMAND             CREATED             STATUS              PORTS               NAMES
    408bd2b9ba53        quay.io/calico/node:{{site.data.versions[page.version].first.title}}   "start_runit"       About an hour ago   Up About an hour                        calico-node

## Next Steps

Now that you have a basic two node CoreOS Container Linux cluster setup, see
[Security using Calico Profiles]({{site.baseurl}}/{{page.version}}/getting-started/docker/tutorials/security-using-calico-profiles)
for a simple security walkthrough.

[virtualbox]: https://www.virtualbox.org/
[vagrant]: https://www.vagrantup.com/downloads.html
[using-coreos]: http://coreos.com/using-coreos/
[curl]: https://curl.haxx.se/
