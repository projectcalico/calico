<!--- master only -->
> ![warning](images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.14.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Expose Container Port to Host-Interface / Internet

In the [Calico without Docker networking tutorial](calico-with-docker/without-docker-networking/README.md) 
or the [Calico as a Docker network plugin tutorial](calico-with-docker/docker-network-plugin/README.md)
we created containers and assigned endpoints (a container interface) to them. This is used for Container-
To-Container communication.

The example below shows how to expose a port of a container to the Host-Interface so this container is 
reachable from outside / the internet.

## Why isn't the `-p` flag on `docker run` working as expected?
If you connect containers to the docker0 interface, then calico would not be able to enforce security rules
between workloads; all containers on the bridge would be able to communicate with each other.

## How can i make a container reachable from the Internet (Host-Interface)?
Let's say you want to expose port 80 of your container IP 192.168.0.1 to be reachable from the internet. 
You can do that these two steps:

### Update Profile to allow traffic to container
First find your profile (see [how to find profile id with docker networking](calico-with-docker/docker-network-plugin/AdvancedPolicy.md))
and add an ibound rule to allow port 80

```
./calicoctl profile <PROFILE> rule add inbound allow tcp to ports 80
```

### Add iptables nat and forwarding rules on your host
Next you need to configure a forwarding rule on your Host-Interafce to port 80 of your container IP

```
iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 80 -j DNAT  --to 192.168.0.1:80
iptables -t nat -A OUTPUT -p tcp -o lo --dport 80 -j DNAT --to-destination 192.168.0.1:80
```

Now all traffic to your Host-Interface on port 80 will be forwarded to the container IP 192.168.0.1

Also check out the [Advanced Network Policy Guide](docs/AdvancedNetworkPolicy.md)
for more information. 
