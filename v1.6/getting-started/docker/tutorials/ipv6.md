---
Title: Calico IPv6 networking as a Docker network plugin (Optional)
---

This tutorial is a continuation of the main
[Calico as a Docker network plugin tutorial](index).

The worked example below focuses on a non-cloud environment.

> Note that it is necessary to use the Calico IPAM driver for running with
> IPv6.

## 1. Pre-requisites

The instructions below assume you have the following hosts with IPv4 addresses configured.
Adjust the instructions accordingly.

| hostname  | IP address   |
|-----------|--------------|
| calico-01 | 172.17.8.101 |
| calico-02 | 172.17.8.102 |

## 2. Add IPv6 addresses to your host

To connect your containers with IPv6, first make sure your Docker hosts each
have an IPv6 address assigned.

On calico-01

    sudo ip addr add fd80:24e2:f998:72d7::1/112 dev enp0s8

On calico-02

    sudo ip addr add fd80:24e2:f998:72d7::2/112 dev enp0s8

Verify connectivity by pinging.

On calico-01

    ping6 -c 4 fd80:24e2:f998:72d7::2

## 3. Restart Calico services with IPv6

Then restart your calico-node processes with the `--ip6` parameter to enable
IPv6 routing.

On calico-01

    sudo calicoctl node --ip=172.17.8.101 --ip6=fd80:24e2:f998:72d7::1 --libnetwork

On calico-02

    sudo calicoctl node --ip=172.17.8.102 --ip6=fd80:24e2:f998:72d7::2 --libnetwork

## 4. Create the networks

To create a network that uses IPv6, it is necessary to specify a "subnet" on
the `docker network create` command which specifies which CIDR the IP addresses
in this network may be allocated from.  You may specify IPv4 and IPv6 CIDRs
individually.

> Note that the current network handling in Docker does not
> allow an IPv6-only network:  if no IPv4 CIDR is specified, then IPv4 addresses
> are assigned from any available IPv4 pool and will fail if there are no
> available pools;  if no IPv6 CIDR is specified, then no IPv6 addresses will
> be assigned, even if there are IPv6 pools configured.
>
> Therefore, to IPv6-enable a network, it is necessary to specify an IPv6
> subnet.

Start by creating an IPv4 and IPv6 pool:

    calicoctl pool add 192.168.0.0/16
    calicoctl pool add fd80:24e2:f998:72d6::/64

To create the networks passing in an IPv6 subnet that exactly matches one of
the configured IPv6 pools (we only created one):

    docker network create --driver calico --ipam-driver calico --subnet fd80:24e2:f998:72d6::/64 net10 --ipv6
    docker network create --driver calico --ipam-driver calico --subnet fd80:24e2:f998:72d6::/64 net11 --ipv6
    docker network create --driver calico --ipam-driver calico --subnet fd80:24e2:f998:72d6::/64 net12 --ipv6

> Note that a particular IP Pool does not have to be confined for use by a single
> network, multiple networks may all reference the same IP Pool.
> The Calico IPAM driver selects unique IPs across all Calico networks and
> containers.  It breaks these larger IP pool CIDRs into smaller ranges that are
> preferentially used on a particular host.

## 5. Create the workloads in the networks

On calico-01

    docker run --net net10 --name workload-V -tid busybox
    docker run --net net11 --name workload-W -tid busybox
    docker run --net net10 --name workload-X -tid busybox

On calico-02

    docker run --net net10 --name workload-Y -tid busybox
    docker run --net net12 --name workload-Z -tid busybox

By default, networks are configured so that their members can communicate with
one another, but workloads in other networks cannot reach them.  V, X and Y are
all in the same network so should be able to ping each other.  W and Z are in
their own networks so shouldn't be able to ping anyone else.

## 6. Validation

On calico-01 check that V can ping X and Y.  It is not possible to ping by
hostname for IPv6, so we need to do a docker inspect to pull out the IPv6
address for a container.

Since V and X are on the same host we can do this as a single command.
On calico-01:

    docker exec workload-V ping6 -c 4 `docker inspect --format "{% raw %}{{ .NetworkSettings.Networks.net10.GlobalIPv6Address }}{% endraw %}" workload-X`

To test connectivity to Y, first obtain the IPv6 address using
`docker inspect` on the host for Y.  On calico-02:

    docker inspect --format "{% raw %}{{ .NetworkSettings.Networks.net10.GlobalIPv6Address }}{% endraw %}" workload-Y

And then run the ping using the inspected IPv6 address.  On calico-01:

    docker exec workload-V ping6 -c 4 <IPv6 address of workload-Y>

replacing the `<...>` with the appropriate IPv6 address of Y.

Also check that V cannot ping W or Z.

Again, since V and W are on the same host, we can run a single command that
inspects the IPv6 address and issues the ping.  On calico-01

    docker exec workload-V ping6 -c 4  `docker inspect --format "{% raw %}{{ .NetworkSettings.Networks.net11.GlobalIPv6Address }}{% endraw %}" workload-W`

These pings will fail.

To test connectivity between V and Z which are on different hosts, run the
`docker inspect` command on the host for Z and then run the ping command on
the host for V.

On calico-02

    docker inspect --format "{% raw %}{{ .NetworkSettings.Networks.net12.GlobalIPv6Address }}{% endraw %}" workload-Z

This returns the IP address of workload-Z.

On calico-01

    docker exec workload-V ping6 -c 4 <IP address of Z>

replacing the `<...>` with the appropriate IP address of D.  These pings will
fail.

To see the list of networks, use

    docker network ls
