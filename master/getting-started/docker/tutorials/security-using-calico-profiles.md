---
title: Security using Calico Profiles
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/docker/tutorials/security-using-calico-profiles'
---

## Background

With {{site.prodname}} as a Docker network plugin, {{site.prodname}} uses an identically named
[profile]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/profile)
to represent each Docker network.  This profile is applied to each container
in that network and the profile is used by {{site.prodname}} to configure access policy
for that container.  The {{site.prodname}} network plugin will automatically create the
associated profile if it does not exist when the container is attached to the
network.  By default, the profile contains rules that allow full egress traffic
but allow ingress traffic only from containers within the same network and no
other source.  Custom policy for a network can be configured by creating in
advance, or editing, the profile associated with the Docker network.

## Tutorial

To run through the worked example in this tutorial you will need to set up two hosts
with {{site.prodname}} installed.

Follow the
[Manual setup]({{site.baseurl}}/{{page.version}}/getting-started/docker/installation/manual)
if you don't already have a cluster prepared.

Or alternatively, use one of the two quickstart clusters:

- [Vagrant install with Container Linux by CoreOS]({{site.baseurl}}/{{page.version}}/getting-started/docker/installation/vagrant-coreos/)
- [Vagrant install with Ubuntu]({{site.baseurl}}/{{page.version}}/getting-started/docker/installation/vagrant-ubuntu)

### 1. Create the network

To create the networks, run the following commands on one of the hosts:

    docker network create --driver calico --ipam-driver calico-ipam net1
    docker network create --driver calico --ipam-driver calico-ipam net2
    docker network create --driver calico --ipam-driver calico-ipam net3

> **Note**: To allocate from a specific {{site.prodname}} IP Pool, the 
> `--subnet a.b.c.d/xx` command can be passed to `docker network create`. 
> For more details see below.
{: .alert .alert-info}

## 2. Create the workloads in the networks

With the networks created, let's start some containers on each host spread
between these networks.

On calico-01

    docker run --net net1 --name workload-A -tid busybox
    docker run --net net2 --name workload-B -tid busybox
    docker run --net net1 --name workload-C -tid busybox

On calico-02

    docker run --net net3 --name workload-D -tid busybox
    docker run --net net1 --name workload-E -tid busybox

By default, networks are configured so that their members can communicate with
one another, but workloads in other networks cannot reach them.  A, C and E are
all in the same network so should be able to ping each other.  B and D are in
their own networks so shouldn't be able to ping anyone else.

## 3. Check Workload Connectivity

On calico-01 check that A can ping C and E.  We can ping workloads within a
containers networks by name.

    docker exec workload-A ping -c 4 workload-C.net1
    docker exec workload-A ping -c 4 workload-E.net1

Also check that A cannot ping B or D.  This is slightly trickier because the
hostnames for different networks will not be added to the host configuration of
the container - so we need to determine the IP addresses assigned to containers
B and D.

Since A and B are on the same host, we can run a single command that inspects
the IP address and issues the ping from A to B. These pings will fail. On calico-01, run:

    docker exec workload-A ping -c 2  `docker inspect --format "{% raw %}{{ .NetworkSettings.Networks.net2.IPAddress }}{% endraw %}" workload-B`


To test connectivity between A and D which are on different hosts, it is
necessary to run the `docker inspect` command on the host for D (calico-02)
and then run the ping command on the host for A (calico-01).

On calico-02:

    docker inspect --format "{% raw %}{{ .NetworkSettings.Networks.net3.IPAddress }}{% endraw %}" workload-D

This returns the IP address of workload-D.

On calico-01:

    docker exec workload-A ping -c 2 <IP address of D>

replacing the `<...>` with the appropriate IP address of D.  These pings will
fail.

To see the list of networks, use:

    docker network ls

## Further Reading

For details on configuring more advanced policy, see
[Security using {{site.prodname}} Profiles and Policy]({{site.baseurl}}/{{page.version}}/getting-started/docker/tutorials/security-using-calico-profiles-and-policy).
