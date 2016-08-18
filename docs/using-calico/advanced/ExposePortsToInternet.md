---
title: # Expose Container Port to Host Interface / Internet
---

In the [Calico without Docker networking tutorial]({{base}}/docs/getting-started/calico-with-docker/without-docker-networking/CalicoAsPlugin)
or the [Calico as a Docker network plugin tutorial]({{base}}/docs/getting-started/calico-with-docker/docker-network-plugin/CalicoWithoutDockerNetworking)
we created containers and assigned endpoints (a container interface) to them. This is used for Container-
To-Container communication.

The example below shows how to expose a port of a container to the host interface so this container is
reachable from outside / the internet.

## Why isn't the `-p` flag on `docker run` working as expected?
If you connect containers to the `docker0` bridge interface, Calico would not
be able to enforce security rules between workloads on the same host; all
containers on the bridge would be able to communicate freely with one other.

> Note: Using Docker networking with the Docker default IPAM driver instructs the
> Calico network driver to route non-network traffic (i.e. destinations outside
> the network CIDR) via the Docker gateway bridge.  Traffic routed through the
> bridge may not be subjected to the policy configured on the host vRouter.

## Exposing Container Port to the Internet (via host interface)
The following steps explain how to expose port 80 of a container with IP
192.168.0.1 to be reachable from the internet via the host.

### Update Profile

First, add a rule to your container's profile to allow inbound TCP traffic to port 80:

> Note: If you are using Calico with Docker networking, you can use the network
> name as the profile.

```shell
calicoctl profile <PROFILE> rule add inbound allow tcp to ports 80
```

### Add iptables nat and forwarding rules on your host
Next, configure a forwarding rule on the host's interface to port 80 of your container IP

```shell
iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 80 -j DNAT  --to 192.168.0.1:80
iptables -t nat -A OUTPUT -p tcp -o lo --dport 80 -j DNAT --to-destination 192.168.0.1:80
```

Now all traffic to your host interface on port 80 will be forwarded to the container IP 192.168.0.1.

For additional information on managing policy for your containers, you can read
the [Advanced Network Policy Guide]({{base}}/docs/using-calico/configuration/AdvancedNetworkPolicy).

