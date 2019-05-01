---
title: Running the Calico rkt tutorials on CoreOS Container Linux using Vagrant and VirtualBox
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/rkt/installation/vagrant-coreos/index'
---

This is a Quick Start guide that uses Vagrant and VirtualBox to create a two-node
Calico cluster that can be used to run through the tutorial for Calico in a
pure rkt environment.

## Environment setup

This section contains the requirements and steps required to ensure your local
environment is correctly configured.

### 1. Install dependencies

You will need to install the following software:

* [VirtualBox][virtualbox] 5.0.0 or greater.
* [Vagrant][vagrant] 1.8.5 or greater.
* [Curl][curl]

### 2 Download the source files

    mkdir demo; cd demo
    curl -O {{site.url}}{{page.dir}}Vagrantfile
    curl -O {{site.url}}{{page.dir}}first-node-config.yaml
    curl -O {{site.url}}{{page.dir}}other-node-config.yaml

### 3. Startup and SSH

To start the cluster, run:

    vagrant up

To connect to your servers:

* Linux/Mac OS X
    * run `vagrant ssh <hostname>`
* Windows
    * Follow instructions from https://github.com/nickryand/vagrant-multi-putty
    * run `vagrant putty <hostname>`

### 4. Verify environment

You should now have two CoreOS Container Linux servers. The servers are named calico-01 and calico-02
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

Check that `rkt` is running on both hosts by running

    sudo rkt list

Verify that `calicoctl` (the Calico CLI) is installed by running

    calicoctl version


### 5. Start the Calico service

Start the Calico service on *both* hosts

```shell
sudo rkt run --stage1-path=/usr/share/rkt/stage1-fly.aci \
  --set-env=ETCD_ENDPOINTS=http://172.18.18.101:2379 \
  --set-env=IP=autodetect \
  --set-env=IP_AUTODETECTION_METHOD=can-reach=172.18.18.101 \
  --insecure-options=image \
  --volume=birdctl,kind=host,source=/var/run/calico,readOnly=false \
  --mount=volume=birdctl,target=/var/run/calico \
  --volume=mods,kind=host,source=/lib/modules,readOnly=false  \
  --mount=volume=mods,target=/lib/modules \
  --volume=logs,kind=host,source=/var/log/calico,readOnly=false \
  --mount=volume=logs,target=/var/log/calico \
  --net=host \
  quay.io/calico/node:{{site.data.versions[page.version].first.title}} &
```

This will create a calico/node rkt container.

You can check that it's running using `sudo rkt list`.

```shell
$ sudo rkt list
UUID      APP	IMAGE NAME                  STATE   CREATED         STARTED         NETWORKS
b52bba11  node  quay.io/calico/node:{{site.data.versions[page.version].first.title}}  running 10 seconds ago  10 seconds ago
```

## Try out Calico networking

Now that you have a basic two node CoreOS Container Linux cluster setup, see the
[Basic Network Isolation guide]({{site.baseurl}}/{{page.version}}/getting-started/rkt/tutorials/basic)
for an example of managing Calico policy with your rkt containers.

[virtualbox]: https://www.virtualbox.org/
[vagrant]: https://www.vagrantup.com/downloads.html
[curl]: https://curl.haxx.se/
