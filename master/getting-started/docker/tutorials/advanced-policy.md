---
title: Accessing Calico policy with Calico as a network plugin
---


## Background

With Calico, a Docker network represents a logical set of rules that define the 
allowed traffic in and out of containers assigned to that network.  The rules
are encapsulated in a Calico "profile".

When creating a Docker network using the Calico network driver, the Calico 
driver creates a profile object for that network.  The default policy applied 
by Calico when a new network is created allows communication between all 
containers connected to that network, and no communication from other networks.

Using the standard `calicoctl create` to create a `profile` resource, it is possible to 
manage the feature-rich policy associated with a network.

> Note that if you want to access the feature rich Calico policy, you must use
> both the Calico Network _and_ Calico IPAM drivers together.  Using the Calico
> IPAM driver ensures _all_ traffic from the container is routed via the host
> vRouter and is subject to Calico policy.

> The profile that is created by the Calico network driver is given the same 
> name as the Docker network name.

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
command specifying `calico` as the network driver and `calico-ipam` as the IPAM driver.

For example, suppose we want to provide network policy for a set of database
containers.  We can create a network called `databases` with the the following
command:

```
docker network create --driver calico --ipam-driver calico-ipam databases 
```

#### Create a profile

To create a profile, we will use `calicoctl create` command with a profile
configured in the YAML format below. The config can also be a yaml file which 
can be passed to the command to create the profile. In this case we're feeding
the config from STDIN.

```
$ cat << EOF | bin/calicoctl create -f -
> apiVersion: v1
> kind: profile
> metadata:
>   name: databases
>   labels:
>    foo: bar
> spec:
>   tags:
>   - tag1
>   - tag2s
>   ingress:
>   - action: deny
>     protocol: tcp
>     icmp:
>        type: 10
>        code: 6
>     notProtocol: udp
>     notICMP:
>        type: 19
>        code: 255
>     source:
>       tag: production
>       net: 10.0.0.0/16
>       selector: type=='application'
>       ports:
>       - 1234
>       - "10:20"
>       notTag: bartag
>       notNet: 10.1.0.0/16
>       notSelector: type=='database'
>       notPorts:
>       - 1050
>     destination:
>       tag: alphatag
>       net: 10.2.0.0/16
>       selector: type=='application'
>       ports:
>       - "100:200"
>       notTag: bananas
>       notNet: 10.3.0.0/16
>       notSelector: type=='apples'
>       notPorts:
>       - "105:110"
>   egress:
>   - action: allow
>     source:
>       selector: type=='application'
> EOF
```

#### View the policy associated with the network

You can use the `calicoctl get -o yaml profile <profile>` to display the
rules in the profile associated with the `databases` network.

```
$ calicoctl get profile databases -o yaml
- apiVersion: v1
  kind: profile
  metadata:
    labels:
      foo: bar
    name: databases
  spec:
    egress:
    - action: allow
      destination: {}
      source:
        selector: type=='application'
    ingress:
    - action: deny
      destination:
        net: 10.2.0.0/16
        notNet: 10.3.0.0/16
        notPorts:
        - 105:110
        notSelector: type=='apples'
        notTag: bananas
        ports:
        - 100:200
        selector: type=='application'
        tag: alphatag
      icmp:
        code: 6
        type: 10
      notICMP:
        code: 255
        type: 19
      notProtocol: udp
      protocol: tcp
      source:
        net: 10.0.0.0/16
        notNet: 10.1.0.0/16
        notPorts:
        - 1050
        notSelector: type=='database'
        notTag: bartag
        ports:
        - 1234
        - "10:20"
        selector: type=='application'
        tag: production
    tags:
    - tag1
    - tag2s
```

As you can see, the default rules allow all outbound traffic and accept inbound
traffic only from containers attached the "databases" network.

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
$ docker network create --driver calico --ipam-driver calico-ipam applications
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

