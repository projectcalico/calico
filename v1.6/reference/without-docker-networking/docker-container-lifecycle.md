---
title: Lifecycle of a container (Calico without Docker networking)
---


This page provides low-level details about what happens within Calico when
Docker containers are networked with Calico when Docker is not providing any
networking.

> The main features covered in this document also apply to the situation
> when Calico is implemented as a Docker network plugin, however, in this case
> many steps are handled automatically by Dockers networking framework and the
> Calico plugin - this will be covered in a future document.

We will start with two hosts and end up with containers on each host that have
connectivity between them.

This walk-through includes details about user actions, the data added to the
etcd datastore and the response of the components that make up the calico-node
container which provides the Calico networking service.

This article has the following sub-sections, each representing a particular
user action:
  - Start Calico on two hosts
  - Create and add containers to Calico
  - Configure endpoints for each container
  - Create a Calico policy profile
  - Associate the Calico endpoints with the profile

## 1. Start Calico on two hosts

User launches the Calico service by running

    calicoctl node

on both hosts (Host1 and Host2).

### System response

The calicoctl utility:

-  Launches a container called `calico-node` on both hosts. The container is
   created from the `calico/node` Docker image.
-  Auto-detects the hosts IP and configures the IP as the BGP address in etcd.
-  Ensures that there are a number of global default values configured in etcd.
   This includes:
   -  The default AS number to use for BGP
   -  Initialising the BGP node-to-node mesh option
-  Configures two default IP Pools (`192.168.0.0/16` and
  `fd80:24e2:f998:72d6::/64`)

Inside the calico-node container:

-  Four key processes are started:  `felix`, `confd` and `bird` and `bird6`
   (see [calico/node container components]({{site.baseurl}}/{{page.version}}/reference/architecture) for more details on
   these).  Since we are not using IPv6, bird6 is not mentioned any further.
-  `felix` is waiting for endpoint data to be configured in etcd.
-  `confd` is monitoring the BGP data in etcd.
    -  On Host1, confd spots the new BGP address for hostB and, writes out a
       configuration file for Bird.  This file contains the configuration
       necessary for a full mesh between all of the BGP peers (in this case
       it is just peering with Host2).  Once the configuration is updated,
       confd signals to BIRD to reload its configuration.
    -  Similar happens on Host2.
-  `bird` has been restarted on Host1 and Host2.  Using the updated
   configuration bird has established BGP peering between the two hosts.  At
   the moment there are no interesting routes programmed on either host and so
   bird is largely idle.  _bird has used the default global AS number
   which was initialized by calicoctl to set up the peering._

![calicoctl node]({{site.baseurl}}/images/lifecycle/calicoctl_node.png)

## 2. Create containers on Host

User creates a Docker container on each host using the `docker run`  command:

    # Host1
    docker run --net=none --name=workload_A -tid ubuntu

    # Host2
    docker run --net=none --name=workload_B -tid ubuntu

### System response

Two ubuntu workloads have been created, one on each host.  The `--net=none`
flag means that the containers are not networked through Docker bridged
networking, so the containers are completely independent and cannot access or
be accessed by outside sources.

There are no changes to any component within the calico-node service.

![docker run]({{site.baseurl}}/images/lifecycle/docker_run.png)

## 3. Add the containers to Calico Networking

User adds the containers to Calico networking by using the `calicoctl container add`
command.  An IP address for both containers is selected from the pre-configured
IPv4 IP Pool.

    # Host1
    calicoctl container add workload_A 192.168.1.1

    # Host2
    calicoctl container add workload_B 192.168.1.2

### System Response

The calicoctl utility:
-  Checks the IP Pools configured in etcd to confirm that the container IP
   value supplied is within a configured pool
-  Creates a veth pair on the host that will be used for the new endpoint (the
   container interface).  It leaves one end in the host's network namespace and
   moves the other end into the container namespace and renames the interface
   in the container
-  Configures the IP address of the interface in the container
-  Sets up a default route over the interface in the container via the host IP
   (the same IP used for the BGP client)
-  Configures the endpoint information in etcd (see below for etcd data format)

Felix spots new endpoint information:
-  Felix programs ACLs into the host's Linux kernel iptables that drop all
   traffic to the container.
-  Felix adds routing table entries to route to the local container via
   the host-side veth for the container.

The BIRD client on each host:
-  Spots that new routes have been added to the host's routing table.
-  BIRD distributes these routes (standard BGP) to all of its BGP peers so
   that each host can then route to containers on the other hosts.  For
   example, host 1 learns about the container on host 2 and programs a route
   to that container via host 2.


![calicoctl container add]({{site.baseurl}}/images/lifecycle/container_add.png)

## 4. Create a Profile

User creates a profile using calicoctl

    calicoctl profile add PROF_A_B

This can be run on either host.

### System Response

The calicoctl utility adds new profile and tag data into the etcd datastore.

At the moment, the profile is not referenced by any endpoints and so Felix
programs no additional iptable rules.

The calicoctl tool can be used to manipulate the rules of a profile to provide
fine grained policy.  In this example, we are using the default configuration
which specifies that any containers that references the profile has full
connectivity to containers also referencing the profile.

![calicoctl profile add]({{site.baseurl}}/images/lifecycle/profile_add.png)

## 5. Update Containers to use the Profile

User updates both containers to add the new profile to the list of profiles
on the container endpoints.

    # Host1
    calicoctl container workload_A profile set PROF_A_B

    # On Host2
    calicoctl container workload_B profile set PROF_A_B

> **NOTE**: Felix deals with endpoints rather than containers, but for simple
> containers with a single interface managed using calicoctl, we treat a
> container and endpoint as the same thing.  For more complicated scenarios,
> calicoctl provides commands for managing actual endpoints (see the
> [`calicoctl endpoint` reference guide]({{site.baseurl}}/{{page.version}}/reference/calicoctl/endpoint) for usage and
> examples).

### System Response

The calicoctl utility:
-  Locates the endpoint (there is assumed to be only one) associated with the
   container
-  Updates the Calico Endpoint configuration by appending the name of the
   profile to the list of profiles in the Endpoint data.

At this point, Felix kicks into action:
-  Felix picks up this change to the endpoint
-  Felix queries the profile and uses the rules of the profile to configure
   iptables rules:
   -  Allow all incoming traffic from other containers using `PROF_A_B`
   -  Drop all other inbound traffic to the containers using `PROF_A_B`
   -  Allow all outbound traffic from the containers using `PROF_A_B`
So now, iptable rules are programmed, local routes are programmed and finally
remote routes are programmed.  Connectivity has been achieved between
endpoints!  The containers are now able to send any kind of traffic to each
other.

![calicoctl container set profile]({{site.baseurl}}/images/lifecycle/set_profile.png)
