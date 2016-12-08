---
title: Calico networking with rkt
---

This tutorial describes how to set up a Calico cluster in a pure rkt environment
using CNI with Calico specific network and IPAM drivers.

## 1. Environment setup

To run through the worked example in this tutorial you will need to set up two hosts
with a number of installation dependencies.

Follow the instructions in the tutorial below to set up a virtualized
environment using Vagrant - be sure to follow the appropriate instructions
for _Running the Calico rkt tutorials on CoreOS using Vagrant and VirtualBox_.

- [Vagrant install with CoreOS]({{site.baseurl}}/{{page.version}}/getting-started/rkt/installation/vagrant-coreos/)

If you have everything set up properly you should have `calicoctl` in your
`$PATH`, and two hosts called `calico-01` and `calico-02`.  The exact
choice of hostname is not important although you will need to adjust these
instructions accordingly based on your actual hostnames.

## 2. Starting Calico services

Once you have your cluster up and running, start Calico on both hosts

```shell
sudo rkt run --stage1-path=/usr/share/rkt/stage1-fly.aci \
  --set-env=ETCD_ENDPOINTS=http://172.18.18.101:2379 \
  --insecure-options=image \
  --volume=birdctl,kind=host,source=/var/run/calico,readOnly=false \
  --mount volume=birdctl,target=/var/run/calico \
  --volume=mods,kind=host,source=/lib/modules,readOnly=false  \
  --mount volume=mods,target=/lib/modules \
  --volume=logs,kind=host,source=/var/log/calico,readOnly=false \
  --mount volume=logs,target=/var/log/calico \
  --set-env=IP=autodetect --net=host quay.io/calico/node:v1.0.0-rc2 &
```

This will create a calico/node rkt container.

You can check that it's running using `sudo rkt list`.

```shell
$ sudo rkt list
UUID      APP	IMAGE NAME                      STATE   CREATED         STARTED         NETWORKS
b52bba11  node  quay.io/calico/node:v1.0.0-rc2  running 10 seconds ago  10 seconds ago
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

## 4. Create containers

With the networks created, let's start some containers. We'll create a "frontend" 
container on `calico-01` and a "backend" container on `calico-02`.
Both containers will just be a `busybox` image running a simple HTTP daemon `httpd`
serving up the containers local filesystem over HTTP.

### On calico-01

Create the "frontend" container.  Note that we include a suffix `:IP=192.168.0.0`, this
is used to pass in the IP environment through to the frontend network plugin which
Calico IPAM uses to assign a specific IP address.  This may be omitted, in which case
Calico IPAM will automatically select an IP address to use from it's configured
IP Pools - however, to simplify this worked we use fixed IP addresses.

```shell
sudo rkt run --net=frontend:IP=192.168.0.0 docker://busybox --exec httpd -- -f -h / &
```

Use `rkt list` to see the IP.

```shell
$ sudo rkt list
UUID      APP      IMAGE NAME                                       STATE   CREATED         STARTED         NETWORKS
6876aae5  busybox  registry-1.docker.io/library/busybox:v1.0.0-rc2  running 11 seconds ago  11 seconds ago  frontend:ip4=192.168.0.0, default-restricted:ip4=172.16.28.2
b52bba11  node     quay.io/calico/node:v1.0.0-rc2                   running 2 minutes ago   2 minutes ago   
```

We now have a `busybox` container running on the network `frontend` with an IP 
address of `192.168.0.0`.  You will see that rkt also creates a second network
called `default-restricted` - this is used for communication with the rkt 
metadata service running on the host and is discussed in the
[rkt documentation](https://github.com/coreos/rkt/blob/master/Documentation/networking/overview.md#the-default-restricted-network).

### On calico-02

Repeat for a "backend" container on `calico-02`

```shell
sudo rkt run --net=backend:IP=192.168.100.0 docker://busybox --exec httpd -- -f -h / &
```

Use `rkt list` to see the container IP.

```shell
$ sudo rkt list
UUID      APP      IMAGE NAME                                       STATE   CREATED        STARTED         NETWORKS
72ce148c  node     quay.io/calico/node:v1.0.0-rc2                   running 4 minutes ago  4 minutes ago   
a2c7ca32  busybox  registry-1.docker.io/library/busybox:v1.0.0-rc2  running 13 seconds ago 12 seconds ago  backend:ip4=192.168.100.0, default-restricted:ip4=172.16.28.2
```

We now have a `busybox` container running on the network `backend` with an IP
address of `192.168.100.0`.

## 5. Validate access to containers

Now that we have created the containers and we know their IP addresses, we can access them using `wget` from containers running on
either host, as long as they are created on the same network.

e.g. On `calico-02` use wget to access the frontend container which is running on `calico-01`

```shell
sudo rkt run --net=frontend docker://busybox --exec=/bin/wget -- -T 3 192.168.0.0/etc/passwd 2>/dev/null
```

Expected output:

```shell
[  576.042144] busybox[5]: Connecting to 192.168.0.0 (192.168.0.0:80)
[  576.046836] busybox[5]: passwd               100% |*******************************|   334   0:00:00 ETA
```

This command runs the `wget` command in a busybox container to fetch the `passwd` file from our host. '-T 3' tells wget to only wait for 3 seconds for a response.
Stderr is redirected to `/dev/null` as we're not interested in the logs from `rkt` for this command.

You can repeat this command on `calico-01` and check that access works the same from any server in your cluster.

### 5 Checking network isolation

Repeat the above command but try to access the backend from the frontend. Because we've not allowed access between these networks, the command will fail.

```shell
sudo rkt run --net=backend docker://busybox --exec=/bin/wget -- -T 3 192.168.0.0/etc/passwd 2>/dev/null
```

Expected output:

```shell
[  621.119210] busybox[5]: Connecting to 192.168.0.0 (192.168.0.0:80)
[  624.120081] busybox[5]: wget: download timed out
```

## 6. Resetting/Cleanup up

If you want to start again from the beginning, then run the following commands on both hosts to ensure that all the rkt containers are removed.

	# Stop the frontend/backend containers
	sudo rkt stop --force <Container_UUID>

	# Remove the stopped containers
	sudo rkt list --no-legend | cut -f1 | sudo xargs rkt rm

	# Wipe Calico data from etcd
	etcdctl rm --recursive /calico
