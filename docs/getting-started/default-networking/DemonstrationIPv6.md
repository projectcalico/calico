<!--- master only -->
> ![warning](../../images/warning.png) This document applies to the HEAD of the calico-docker source tree.
>
> View the calico-docker documentation for the latest release [here](https://github.com/projectcalico/calico-docker/blob/v0.12.0/README.md).
<!--- else
> You are viewing the calico-docker documentation for release **release**.
<!--- end of master only -->

# Calico IPv6 networking with Docker Default Networking (Optional)

This tutorial is a continuation of the main 
[default networking demonstration](Demonstration.md).  The instructions below 
assume you have the following hosts with IPv4 addresses configured.  Adjust the
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

    sudo calicoctl node --ip=172.17.8.101 --ip6=fd80:24e2:f998:72d7::1

On calico-02

    sudo calicoctl node --ip=172.17.8.102 --ip6=fd80:24e2:f998:72d7::2

Then, you can start containers with IPv6 connectivity. By default, Calico is 
configured to use IPv6 addresses in the pool fd80:24e2:f998:72d6/64 
(use `calicoctl pool add` to change this).

On calico-01, create a container:

    docker run --name workload-F -tid ubuntu

Then add the container to Calico networking with an IPv6 address:

    sudo calicoctl container add workload-F fd80:24e2:f998:72d6::1

Note that we have used `ubuntu` instead of `busybox`.  Busybox doesn't support 
IPv6 versions of network tools like ping.

On calico-02, create a container and add it to Calico networking:

    docker run --name workload-G -tid ubuntu
    sudo calicoctl container add workload-G fd80:24e2:f998:72d6::2

Now create a security profile and set the profile on the two containers.

On either calico host:

    calicoctl profile add PROF_F_G

On calico-01:

    calicoctl container workload-F profile append PROF_F_G

On calico-02:

    calicoctl container workload-G profile append PROF_F_G

Now you can ping between the two containers using their IPv6 addresses.

On calico-02:

    docker exec workload-G ping6 -c 4 fd80:24e2:f998:72d6::1
