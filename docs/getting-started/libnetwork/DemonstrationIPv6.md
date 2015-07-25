# Calico IPv6 networking with libnetwork (Optional)

This tutorial is a continuation of the main 
[libnetwork demonstration](Demonstration.md).  The instructions below assume
you have the following hosts with IPv4 addresses configured.  Adjust the
instructions accordingly.

| hostname  | IP address   |		
|-----------|--------------|		
| calico-01 | 172.17.8.101 |		
| calico-02 | 172.17.8.102 |

To connect your containers with IPv6, first make sure your Docker hosts each 
have an IPv6 address assigned.

On calico-01

    sudo ip addr add fd80:24e2:f998:72d7::1/112 dev eth1

On calico-02

    sudo ip addr add fd80:24e2:f998:72d7::2/112 dev eth1

Verify connectivity by pinging.

On calico-01

    ping6 -c 4 fd80:24e2:f998:72d7::2

Then restart your calico-node processes with the `--ip6` parameter to enable 
v6 routing.

On calico-01

    calicoctl node --ip=172.17.8.101 --ip6=fd80:24e2:f998:72d7::1

On calico-02

    calicoctl node --ip=172.17.8.102 --ip6=fd80:24e2:f998:72d7::2

Then, you can start containers with IPv6 connectivity. By default, Calico is 
configured to use IPv6 addresses in the pool fd80:24e2:f998:72d6/64 
(`calicoctl pool add` to change this).

On calico-01

    docker run --publish-service srvF.net4.calico --name workload-F -tid ubuntu

Then get the ipv6 address of workload-F

    docker inspect --format "{{ .NetworkSettings.GlobalIPv6Address }}" workload-F

Note that we have used `ubuntu` instead of `busybox`.  Busybox doesn't support 
IPv6 versions of network tools like ping.

One calico-02

    docker run --publish-service srvG.net4.calico --name workload-G -tid ubuntu

Then ping workload-F via its ipv6 address that you received above (change the 
IP address if necessary):

    docker exec workload-G ping6 -c 4 fd80:24e2:f998:72d6::1
