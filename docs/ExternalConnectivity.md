<!--- master only -->
> ![warning](images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# External Connectivity - Hosts on their own Layer 2 segment

Calico creates a routed network on which your containers look like normal IP 
speakers.  You can connect to them from a host in your cluster (assuming the 
network policy you've assigned allows this) using their IP address.

In order to access your containers from locations other than your cluster of 
hosts, you will need to configure IP routing.

A common scenario is for your container hosts to be on their own isolated layer
2 network, like a rack in your server room or an entire data center.  Access to
that network is via a router, which also is the default router for all the
container hosts.

![hosts-on-layer-2-network](images/hosts-on-layer-2-network.png)

If this describes your infrastructure, you'll need to configure that router to
communicate with the Calico-enabled hosts over BGP.  If you have a small number
of hosts, you can configure BGP sessions between your router and each
Calico-enabled host.

The Calico network defaults to AS number 64511, which is in the private range,
and therefore will not conflict with anything else on the public internet. 
However, if your organization is already using AS number 64511, you should
change the Calico cluster to use a different private AS number.  See the 
[BGP Configuration tutorial](bgp.md) for how to do this.

Then, on one of your Calico-enabled hosts, configure the session to your
router.  Let's say your router's IP address is 192.20.30.40 and it is in AS
number 64567:

    $ calicoctl bgp peer add 192.20.30.40 as 64567

You only need to do this on one Calico-enabled host; you have configured a
global BGP peer and every host in your cluster will attempt to peer with it
(see the [BGP Configuration tutorial](bgp.md) for more detail).

Lastly, you'll need to configure your router.  Consult your router's
configuration guide for the exact steps, but generally speaking, you'll need to

 1. enable BGP if it hasn't already been enabled
 2. configure each Calico-enabled host as a BGP peer
 3. announce the range of IP addresses used by your containers to the rest of your network

If you have a L3 routed fabric or some other scenario not covered by the above,
detailed datacenter networking recommendations are given in the main 
[Project Calico documentation](http://docs.projectcalico.org/en/latest/index.html).
We'd also encourage you to [get in touch](http://www.projectcalico.org/contact/)
to discuss your environment.
[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/ExternalConnectivity.md?pixel)](https://github.com/igrigorik/ga-beacon)
