---
title: Basic Network Isolation
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/rkt/tutorials/basic'
---

This guide provides a simple way to try out rkt network isolation with Calico.
It requires a cluster of nodes configured with Calico networking, and expects
that you have `rkt` installed and `calicoctl` configured to interact with the
cluster.

You can quickly and easily deploy such a cluster by following one of the
[getting started guides]({{site.baseurl}}/{{page.version}}/getting-started/rkt#installation-guides)

For simplicity, we assume you have a two node cluster with the node names
`calico-01` and `calico-02`.  If your nodes have different names, adjust the
instructions accordingly.

## 1. Verify Calico service is running

Your installation should have installed and started the Calico service on each node.  You
can check that it's running using `sudo rkt list`.

```shell
$ sudo rkt list
UUID      APP	IMAGE NAME                  STATE   CREATED         STARTED         NETWORKS
b52bba11  node  quay.io/calico/node:{{site.data.versions[page.version].first.components["calico/node"].version}}  running 10 seconds ago  10 seconds ago
```

## 2. Create the networks

You can configure multiple networks when using rkt. Each network is represented by a configuration file in
`/etc/rkt/net.d/`. By default, when using Calico CNI, connections to a given container are only allowed
from containers on the same network. This can be changed by applying additional Calico policy - which will
be discussed in advanced tutorials.

To define a rkt network for Calico, create a configuration file in `/etc/rkt/net.d/`.

- Each network should be given a unique "name".
- To use Calico networking, specify "type": "calico"
- To use Calico IPAM, specify "type": "calico-ipam" in the "ipam" section.

Calico will create an identically named profile for each Calico-rkt network, by
default the policy specified in the profile allows full communication between containers within the same
network (i.e. using the same profile) but prohibits ingress traffic from containers
on other networks.

This worked example creates two rkt networks. Run these commands on both `calico-01` and `calico-02`

```shell
cat >/etc/rkt/net.d/10-calico-network1.conf <<EOF
{
    "name": "network1",
    "cniVersion": "0.1.0",
    "type": "calico",
    "ipam": {
        "type": "calico-ipam"
    }
}
EOF

cat >/etc/rkt/net.d/10-calico-network2.conf <<EOF
{
    "name": "network2",
    "cniVersion": "0.1.0",
    "type": "calico",
    "ipam": {
        "type": "calico-ipam"
    }
}
EOF
```

## 3. Create test container

With the networks created, let's start some containers. We'll create a
container on `calico-01` in `network1`, and then create containers on `calico-02`
in each network to check connectivity to the first container.  For this tutorial,
the container we create on `calico-01` will be a `busybox` image running a simple HTTP daemon `httpd`
serving up the containers local filesystem over HTTP.

### On calico-01

Create the container in `network1`.  Note that we include a suffix `:IP=192.168.0.0`, this
is used to pass the IP environment through to the network plugin which
Calico IPAM uses to assign a specific IP address.  We use a fixed IP address to
simplify the steps in this tutorial, however if the suffix is omitted, Calico IPAM will
automatically select an IP address to use from it's configured IP Pools.

```shell
sudo rkt run --net=network1:IP=192.168.0.0 docker://busybox --exec httpd -- -f -h / &
```

Use `rkt list` to see the IP.

```shell
$ sudo rkt list
UUID      APP      IMAGE NAME                                   STATE   CREATED         STARTED         NETWORKS
6876aae5  busybox  registry-1.docker.io/library/busybox:latest  running 11 seconds ago  11 seconds ago  network1:ip4=192.168.0.0, default-restricted:ip4=172.16.28.2
b52bba11  node     quay.io/calico/node:{{site.data.versions[page.version].first.components["calico/node"].version}}                   running 2 minutes ago   2 minutes ago
```

We now have a `busybox` container running on the network `network1` with an IP
address of `192.168.0.0`.  You will see that rkt also creates a second network
called `default-restricted` - this is used for communication with the rkt
metadata service running on the host and is discussed in the
[rkt documentation](https://github.com/coreos/rkt/blob/master/Documentation/networking/overview.md#the-default-restricted-network).

## 4. Validate intra-network connectivity

Now that we have created the container on `calico-01` and we know its IP address.
We can access it using `wget` from containers running on
either host, as long as they are created in the same network.

e.g. On `calico-02` use wget to access the container running on `calico-01`

```shell
sudo rkt run --net=network1 docker://busybox --exec=/bin/wget -- -T 3 192.168.0.0/etc/passwd 2>/dev/null
```

Expected output:

```shell
[  576.042144] busybox[5]: Connecting to 192.168.0.0 (192.168.0.0:80)
[  576.046836] busybox[5]: passwd               100% |*******************************|   334   0:00:00 ETA
```

This command runs the `wget` command in a busybox container to fetch the `passwd` file from our host.
'-T 3' tells wget to only wait for 3 seconds for a response. Stderr is redirected to `/dev/null` as we're
not interested in the logs from `rkt` for this command.

You can repeat this command on `calico-01` and check that access works the same
from any server in your cluster.

### 5. Checking inter-network isolation

Repeat the above command but try to access the container on `calico-01` from network2.
Because we've not allowed access between these networks, the command will fail.

```shell
sudo rkt run --net=network2 docker://busybox --exec=/bin/wget -- -T 3 192.168.0.0/etc/passwd 2>/dev/null
```

Expected output:

```shell
[  621.119210] busybox[5]: Connecting to 192.168.0.0 (192.168.0.0:80)
[  624.120081] busybox[5]: wget: download timed out
```

### 6. Verify Calico profiles were created

You can use the `calicoctl get profiles` command line tool to verify that the Calico CNI
plugin created two profiles, `network1` and `network2`:

```shell
$ calicoctl get profiles
NAME
network1
network2
```

## 7. Resetting/Cleanup

If you want to start again from the beginning, then run the following commands on both hosts to ensure that all the rkt containers are removed.

```shell
# Stop the network1/network2 containers
sudo rkt stop --force <Container_UUID>

# Remove the stopped containers
sudo rkt list --no-legend | cut -f1 | sudo xargs rkt rm
```

