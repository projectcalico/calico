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

---
title: Calico networking with rkt
---


This tutorial describes how to set up a Calico cluster in a pure rkt environment
using CNI with Calico specific network and IPAM drivers.

Using the Calico CNI plugin, the required network setup and configuration
for networking containers using Calico is handled automatically as part of the
standard network and container lifecycle.  Provided the network is created
using the Calico driver, creating a container using that network will
automatically add the container to the Calico network, creating all necessary
Calico configuration and setting up the interface and routes in the container
accordingly.

The Calico IPAM driver must be used in addition to the the Calico network
driver.  This provides IP address management using the configured Calico IP
Pools as address pools for the container, preferentially selecting sub-blocks
of IPs for a particular host.

## 1. Environment setup

To run through the worked example in this tutorial you will need to set up two hosts
with a number of installation dependencies.

Follow the instructions in the tutorial below to set up a virtualized
environment using Vagrant - be sure to follow the appropriate instructions
for _Running the Calico rkt tutorials on CoreOS using Vagrant and VirtualBox_.

- [Vagrant install with CoreOS]({{site.baseurl}}/{{page.version}}/getting-started/rkt/installation/vagrant-coreos/)


If you have everything set up properly you should have `calicoctl` in your
`$PATH`, and two hosts called `calico-01` and `calico-02`.

## 2. Starting Calico services

Once you have your cluster up and running, start Calico on both hosts

```shell
sudo rkt run --stage1-path=/usr/share/rkt/stage1-fly.aci --set-env=ETCD_ENDPOINTS=http://172.18.18.101:2379 --insecure-options=image --volume=birdctl,kind=host,source=/var/run/calico,readOnly=false --mount volume=birdctl,target=/var/run/calico --volume=mods,kind=host,source=/lib/modules,readOnly=false  --mount volume=mods,target=/lib/modules --volume=logs,kind=host,source=/var/log/calico,readOnly=false --mount volume=logs,target=/var/log/calico --set-env=IP=autodetect --net=host quay.io/calico/node:v1.0.0-rc1 &
```

This will create a rkt container called `calico-node`.

You can check that it's running

```shell
$ sudo rkt list
UUID		APP	    IMAGE NAME			            STATE	CREATED		    STARTED		   NETWORKS
6e552eeb	node	quay.io/calico/node:v1.0.0-rc1	running	20 seconds ago	20 seconds ago
```

## 3. Create the networks

You can configure multiple networks when using rkt. Each network is represented by a configuration file in
`/etc/rkt/net.d/`. By default, connections to a given container are only allowed from containers on the same network.
This can be changed by applying additional Calico policy.

Containers on multiple networks can be accessed by containers on each network that it is connected to.
- The container only gets a single Calico IP address and single ethernet interface.
- The container is associated with the Calico profiles for each of the networks.

To define a rkt network for Calico, create a configuration file in `/etc/rkt/net.d/`.
- Each network should be given a unique "name". This corresponds to a "profile" in Calico.
- To use Calico networking, specify "type": "calico"
- To use Calico IPAM, specify "type": "calico-ipam" in the "ipam" section.

This worked example creates two rkt networks. Run these commands on both `calico-01` and `calico-02`

```shell
cat >/etc/rkt/net.d/10-calico-backend.conf <<EOF
{
    "name": "backend",
    "type": "calico",
    "ipam": {
        "type": "calico-ipam"
    }
}
EOF

cat >/etc/rkt/net.d/10-calico-frontend.conf <<EOF
{
    "name": "frontend",
    "type": "calico",
    "ipam": {
        "type": "calico-ipam"
    }
}
EOF
```

## 4. Create services

With the networks created, let's start some services. We'll create a "frontend" and a "backend" service, one on `calico-01` and the other on `calico-02`
Both "services" will just be a `httpd` running in a `busybox` container. The service just serves up the filesystem in the container over HTTP.

### On calico-01

Create the "frontend" service.

```shell
sudo rkt run --net=backend docker://busybox --exec httpd -- -f -h / &
```

Use `rkt list` to see the IP.

```shell
$ sudo rkt list
UUID		APP		IMAGE NAME									STATE	CREATED			STARTED			NETWORKS
6e552eeb	node	quay.io/calico/node:v1.0.0-rc1				running	7 minutes ago	7 minutes ago
fe706423	busybox	registry-1.docker.io/library/busybox:latest	running	9 seconds ago	8 seconds ago	frontend:ip4=192.168.212.129, default-restricted:ip4=172.16.28.2
```

We now have a `busybox` container running on the network `frontend` with an IP address of `192.168.212.129`
rkt also creates a second network called `default-restricted`. This is used for communication with the rkt metadata service running on the host and is covered in the [rkt documentation](https://github.com/coreos/rkt/blob/master/Documentation/networking/overview.md#the-default-restricted-network)

### On calico-02

Repeat for a "backend" service on `calico-02`

```shell
sudo rkt run --net=backend docker://busybox --exec httpd -- -f -h / &
```

Use `rkt list` to see the container IP.

```shell
$ sudo rkt list
UUID		APP		IMAGE NAME									STATE	CREATED			STARTED			NETWORKS
33ce4f2b	node	quay.io/calico/node:v1.0.0-rc1				running	1 minute ago	1 minute ago
7e7315af	busybox	registry-1.docker.io/library/busybox:latest	running	15 seconds ago	15 seconds ago	backend:ip4=192.168.138.64, default-restricted:ip4=172.16.28.2
```

We now have a `busybox` container running on the network `backend` with an IP address of `192.168.138.64`

## 5. Validate access to services

Now that we have created the services and we know their IP addresses, we can access them using `wget` from containers running on
either host, as long as they are created on the same network.

e.g. On `calico-02` use wget to access the frontend service which is running on `calico-01`

```shell
sudo rkt run --net=frontend docker://busybox --exec=/bin/wget -- -T 3 192.168.212.129/etc/passwd 2>/dev/null
```

Expected output:

```shell
[62032.807862] wget[4]: Connecting to 192.168.212.129 (192.168.212.129:80)
[62032.813662] wget[4]: passwd               100% |*******************************|   334   0:00:00 ETA
```

This command runs the `wget` command in a busybox container to fetch the `passwd` file from our host. '-T 3' tells wget to only wait for 3 seconds for a response.
Stderr is redirected to `/dev/null` as we're not interested in the logs from `rkt` for this command.

You can repeat this command on `calico-01` and check that access works the same from any server in your cluster.

### 5 Checking network isolation

Repeat the above command but try to access the backend from the frontend. Because we've not allowed access between these networks, the command will fail.

```shell
sudo rkt run --net=backend docker://busybox --exec=/bin/wget -- -T 3 192.168.212.129/etc/passwd 2>/dev/null
```

Expected output:

```shell
[62128.109283] wget[4]: Connecting to 192.168.212.129 (192.168.212.129:80)
[62129.109472] wget[4]: wget: download timed out
```

## 6. Resetting/Cleanup up

If you want to start again from the beginning, then run the following commands on both hosts to ensure that all the rkt containers are removed.

	# Stop the frontend/backend containers and calico-node container
	sudo rkt stop --force <Container_UUID>

	# Remove the stopped containers
	sudo rkt list --no-legend | cut -f1 |sudo xargs rkt rm

	# Wipe Calico data from etcd
	etcdctl rm --recursive /calico
