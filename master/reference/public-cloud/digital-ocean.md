---
title: Calico on Digital Ocean
---

Calico is designed to provide high performance massively scalable virtual
networking for containers in public cloud environments such as Digital Ocean.

## How to Run Calico in Digital Ocean

Digital Ocean offers two networking options for droplets:

- Public Interface
- Private Interface

Calico can be launched on either.
We recommend running Calico on the private interface, as it enhances security by
ensuring Calico services are not accessible from the wider internet.

However, hosts in different Datacenter Regions will not have IP connectivity with one
another through their private address, and therefore will not be able to establish
BGP sessions with one another. For mluti-region Digital Ocean clusters,
bind Calico to the public interface.

###### Enable Encapsulation

In Digital Ocean, cross-host container-to-container traffic will travel over at least one
L3 hop. Since Digital Ocean does not allow peering to its networking fabric, it will
not know how to route this container traffic, and will drop it.

To remedy this, Calico can encapsulate container traffic with the IP so that the
networking fabric never sees the container IPs, allowing standard routing to
take over. Turn on traffic encapsulation in pool settings by enabling:

- `ipip` for container-to-container traffic.
- `nat-outgoing` for container-to-droplet traffic.

See [pool configuration]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool) for information on how to enable this for IP pools.

###### Ensure Calico Chooses Correct IP

Note that calicoctl's automatic IP detection will launch calico/node on the private
address if the droplet is configured to have a private interface.

Ensure you manually specify `--ip` when launching `calicoctl node run` if you
want it to bind to the public interface.
