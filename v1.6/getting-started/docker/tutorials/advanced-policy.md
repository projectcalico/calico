---
title: Accessing Calico policy with Calico as a network plugin
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v2.0/getting-started/docker/tutorials/advanced-policy'
---


## Background

With Calico, a Docker network represents a logical set of rules that define the 
allowed traffic in and out of containers assigned to that network.  The rules
are encapsulated in a Calico "profile".

When creating a Docker network using the Calico network driver, the Calico 
driver creates a profile object for that network.  The default policy applied 
by Calico when a new network is created allows communication between all 
containers connected to that network, and no communication from other networks.

Using the standard `calicoctl profile` commands it is possible to manage the
feature-rich policy associated with a network.

> Note that if you want to access the feature rich Calico policy, you must use
> both the Calico Network _and_ Calico IPAM drivers together.  Using the Calico
> IPAM driver ensures _all_ traffic from the container is routed via the host
> vRouter and is subject to Calico policy. Using the default IPAM driver 
> instructs the Calico network driver to route non-network traffic (i.e.
> destinations outside the network CIDR) via the Docker gateway bridge, and in
> this case may not be subjected to the policy configured on the host vRouter.

> The profile that is created by the Calico network driver is given the same 
> name as the Docker-generated network ID.  This can be cumbersome to work
> with, so the `calicoctl` tool that is used to manage the network policy 
> handles the mapping between network names and IDs.  For the most part,
> the detail about network IDs can be ignored, but it is mentioned here as a
> side note for advanced users and developers,

## Multiple networks

Whilst the Docker API supports the ability to attach a container to multiple
networks, it is not possible to use this feature of Docker when using Calico
as the networking and IPAM provider.

However, by defining multiple networks and modifying the Calico policy 
associated with those networks it is possible to achieve the same isolation 
that you would have if using multiple networks, with the additional bonus of a
much richer policy set.

For example, suppose with a standard Docker network approach you have two 
networks A and B, and you have set of containers on network A, some on network
B, and some on both networks A and B.  When using Calico as a Docker network
plugin, you would configure networks A and B and then configure a third network
(lets call it AB) to represent the "A and B" group where the policy would be
modified to allow ingress traffic from both A and B.  Rather than attaching a
container to network A and network B, with this model you would attach the 
container to network AB.

## Managing Calico policy for a network

This section walks through an example of creating a docker network (with
Calico) and using the `calicoctl` command line interface to modify the policy
associated with that network.

#### Create a Docker network

To create a Docker network using Calico, run the `docker network create`
command specifying "calico" as both the network and IPAM driver.

For example, suppose we want to provide network policy for a set of database
containers.  We can create a network called `databases` with the the following
command:

```
docker network create --driver calico --ipam-driver calico databases 
```

#### View the policy associated with the network

You can use the `calicoctl profile <profile> rule show` to display the
rules in the profile associated with the `databases` network.

The network name can be supplied as the profile name and the `calicoctl` tool
will look up the profile associated with that network.

```
$ calicoctl profile databases rule show
Inbound rules:
   1 allow from tag databases
Outbound rules:
   1 allow
```

As you can see, the default rules allow all outbound traffic and accept inbound
traffic only from containers attached the "databases" network.

> Note that when managing profiles created by the Calico network driver, the
> tag and network name can be regarded as the same thing.

#### Configuring the network policy

Calico has a rich set of policy rules that can be leveraged.  Rules can be
created to allow and disallow packets based on a variety of parameters such
as source and destination CIDR, port and tag.

The `calicoctl profile <profile> rule add` and `calicoctl profile <profile> rule remove`
commands can be used to add and remove rules in the profile.
  
As an example, suppose the databases network represents a group of MySQL
databases which should allow TCP traffic to port 3306 from "application" 
containers.

To achieve that, create a second network called "applications" which the
application containers will be attached to.  Then, modify the network policy of
the databases to allow the appropriate inbound traffic from the applications.

```
$ docker network create --driver calico --ipam-driver calico applications
$ calicoctl profile databases rule add inbound allow tcp from tag applications to ports 3306
```

The second command adds a new rule to the databases network policy that allows
inbound TCP traffic from the applications.

You can view the updated network policy of the databases to show the newly
added rule:

```
$ calicoctl profile databases rule show
Inbound rules:
   1 allow from tag databases
   2 allow tcp from tag applications to ports 3306
Outbound rules:
   1 allow
```

For more details on the syntax of the rules, run `calicoctl profile --help` to
display the valid profile commands.

## Further reading

For more details about advanced policy options read the 
[Advanced Network Policy tutorial]({{site.baseurl}}/{{page.version}}/usage/configuration/advanced-network-policy).

