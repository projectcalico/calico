---
title: Calico Networking with rkt
canonical_url: 'https://docs.projectcalico.org/v1.6/getting-started/rkt/vagrant/index'
---

This tutorial describes how to set up a Calico cluster in a pure rkt environment.
rkt is used for running both the Calico components and the workloads.

## 1. Environment setup

This tutorial walks through getting a cluster set up with Vagrant.

### 1.1 Install dependencies

* [VirtualBox][virtualbox] 5.0.0 or greater.
* [Vagrant][vagrant] 1.7.4 or greater.
* [Git][git]

### 1.2 Clone this project

    git clone https://github.com/projectcalico/calico.git

### 1.3 Startup and SSH
Change into the directory for this guide:

    cd calico/{{page.version}}/getting-started/rkt/vagrant/

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

    curl -L http://localhost:2379/version


## 2. Starting Calico services

Once you have your cluster up and running, start Calico on both hosts

    sudo calicoctl node  --runtime=rkt

This will create a systemd unit called `calico-node` which runs the Calico components under `rkt`

You can check that it's running

	$ sudo rkt list
	UUID            APP     IMAGE NAME                              STATE   NETWORKS
	bc13af40        node    registry-1.docker.io/calico/node:v0.23.1 running

You can check the status and logs using normal systemd commands e.g. `systemctl status calico-node` and `journalctl -u calico-node`

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

Create the "frontend" service using `systemd-run`.

    sudo systemd-run --unit=frontend sudo rkt run --net=frontend registry-1.docker.io/library/busybox --exec httpd -- -f -h /

Normal [systemd commands][systemd-run] can then be used to get the status of the container and view its logs (e.g. `sudo journalctl -u frontend`). Use `rkt list` to see the IP.

	$ sudo rkt list
	UUID		APP	IMAGE NAME					STATE	CREATED		STARTEDNETWORKS
	05f8779a	node	registry-1.docker.io/calico/node:v0.23.1		running	1 hour ago	1 hour ago
	c89f2f35	busybox	registry-1.docker.io/library/busybox:latest	running	2 seconds ago	1 second ago	frontend:ip4=192.168.0.0, default-restricted:ip4=172.16.28.2


We now have a `busybox` container running on the network `frontend` with an IP address of `192.168.0.0`
rkt also creates a second network called `default-restricted`. This is used for communication with the rkt metadata service running on the host and is covered in the [rkt documentation](https://github.com/coreos/rkt/blob/master/Documentation/networking/overview.md#the-default-restricted-network)

### On calico-02

Repeat for a "backend" service on `calico-02`

    sudo systemd-run --unit=backend sudo rkt run --net=backend registry-1.docker.io/library/busybox --exec httpd -- -f -h /

	$ sudo rkt list
	UUID		APP	IMAGE NAME					STATE	CREATED		STARTEDNETWORKS
	2cc27ce1	node	registry-1.docker.io/calico/node:v0.23.1		running	1 hour ago	1 hour ago
	407208a5	busybox	registry-1.docker.io/library/busybox:latest	running	11 seconds ago	10 seconds ago	backend:ip4=192.168.0.64, default-restricted:ip4=172.16.28.2

We now have a `busybox` container running on the network `backend` with an IP address of `192.168.0.1`

## 5. Validate access to services

Now that we've created the services and we know their IP addresses, we can access them using `wget` from containers running on
either host, as long as they are created on the same network.

e.g. On `calico-02` use wget to access the frontend service which is running on `calico-01`

	sudo rkt run --net=frontend registry-1.docker.io/library/busybox --exec=/bin/wget -- -T 10 192.168.0.0/etc/passwd 2>/dev/null

Expected output

	[62032.807862] wget[4]: Connecting to 192.168.0.0 (192.168.0.0:80)
	[62032.813662] wget[4]: passwd               100% |*******************************|   334   0:00:00 ETA

This command runs the `wget` command in a busybox container to fetch the `passwd` file from our host. '-T 1' tells wget to only wait a second for a response.
Stderr is redirected to `/dev/null` as we're not interested in the logs from `rkt` for this command.

You can repeat this command on calico-01 and check that access works the same from any server in your cluster.

### 5.1 Checking network isolation
Repeat the above command but try to access the backend from the frontend. Because we've not allowed access between these networks, the command will fail.

	sudo rkt run --net=backend registry-1.docker.io/library/busybox --exec=/bin/wget -- -T 2 192.168.0.0/etc/passwd 2>/dev/null

Expected output

	[62128.109283] wget[4]: Connecting to 192.168.0.0 (192.168.0.0:80)
	[62129.109472] wget[4]: wget: download timed out

Calico always allows access to the containers running on a host _from that host only_. The rules are bypassed in this case only.
This means that the backend service can be accessed directly from `calico-02` (the host it's running on), but not from `calico-01`

## 6. Add network policy
To view the existing network policy, use the `calicoctl` command.

On either host, run

	calicoctl profile backend rule show

Expected output

	Inbound rules:
		 1 allow from tag backend
	Outbound rules:
		 1 allow

The "frontend" profile produces a similar result.

### Open access to backends

We want the backends to allow inbound traffic from the frontends, but only on port 80.

Run

	calicoctl profile backend rule add inbound allow tcp from tag frontend to ports 80
	calicoctl profile backend rule show

To produce the following output

	Inbound rules:
		 1 allow from tag backend
		 2 allow tcp from tag frontend to ports 80
	Outbound rules:
		 1 allow

And we can now access our backend service from the frontend containers.

On either host, run

	sudo rkt run --net=frontend registry-1.docker.io/library/busybox --exec=/bin/wget -- -T 10 192.168.0.64/etc/passwd 2>/dev/null

### Open access to frontends
We want to allow everyone to access our frontends, but only on port 80.

	calicoctl profile frontend rule add inbound allow tcp to ports 80
	calicoctl profile frontend rule show

To produce the following output

	calicoctl profile frontend rule show
	Inbound rules:
		 1 allow from tag frontend
		 2 allow tcp to ports 80
	Outbound rules:
		 1 allow

Now on either host, we can access the container directly

	wget -T 10 192.168.0.0/etc/passwd

## 7. Resetting/Cleanup up
If you want to start again from the beginning, then run the following commands on both hosts to ensure that all the rkt containers and systemd jobs are removed.

	# Stop the frontend (in case the job failed, manually remove the service too)
	sudo systemctl stop frontend; sudo rm -rf /run/systemd/system/frontend.service /run/systemd/system/frontend.service.d; sudo systemctl daemon-reload

	# Stop the backend (in case the job failed, manually remove the service too)
	sudo systemctl stop backend; sudo rm -rf /run/systemd/system/backend.service /run/systemd/system/backend.service.d; sudo systemctl daemon-reload

	# Stop the calico-node (in case the job failed, manually remove the service too)
	sudo systemctl stop calico-node; sudo rm -rf /run/systemd/system/calico-node.service /run/systemd/system/calico-node.service.d; sudo systemctl daemon-reload

	# Remove any stopped busybox containers
	sudo rkt list --no-legend | cut -f1 |sudo xargs rkt rm

	# Wipe Calico data from etcd
	etcdctl rm --recursive /calico


[systemd-run]: https://github.com/coreos/rkt/blob/master/Documentation/using-rkt-with-systemd.md#systemd-run
[virtualbox]: https://www.virtualbox.org/
[vagrant]: https://www.vagrantup.com/downloads.html
[git]: http://git-scm.com/
