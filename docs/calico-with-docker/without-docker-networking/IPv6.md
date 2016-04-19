<!--- master only -->
> ![warning](../../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Calico IPv6 networking without Docker networking (Optional)

This tutorial is a continuation of the main 
[Calico without Docker networking tutorial](README.md).

The worked example below focuses on a non-cloud environment.
  
## 1. Pre-requisites

The instructions below assume you have the following hosts with IPv4 addresses
configured. Adjust the instructions accordingly.

| hostname  | IP address   |
|-----------|--------------|
| calico-01 | 172.17.8.101 |
| calico-02 | 172.17.8.102 |

## 2. Add IPv6 addresses to your host

To connect your containers with IPv6, first make sure your Docker hosts each 
have an IPv6 address assigned.

On calico-01

    sudo ip addr add fd80:24e2:f998:72d7::1/112 dev eth1

On calico-02

    sudo ip addr add fd80:24e2:f998:72d7::2/112 dev eth1

Verify connectivity by pinging.

On calico-01

    ping6 -c 4 fd80:24e2:f998:72d7::2

## 3. Restart Calico services with IPv6

Then restart your calico-node processes with the `--ip6` parameter to enable 
v6 routing.

On calico-01

    sudo calicoctl node --ip=172.17.8.101 --ip6=fd80:24e2:f998:72d7::1

On calico-02

    sudo calicoctl node --ip=172.17.8.102 --ip6=fd80:24e2:f998:72d7::2

## 4. Starting containers

Then, you can start containers with IPv6 connectivity. By default, Calico is 
configured to use IPv6 addresses in the pool fd80:24e2:f998:72d6/64 
(use `calicoctl pool add` to change this).

On calico-01, run:

    docker run --name workload-F -tid ubuntu

On calico-02, run:

    docker run --name workload-G -tid ubuntu

> Note that we have used `ubuntu` instead of `busybox`.  Busybox doesn't support 
> IPv6 versions of network tools like ping.

## 5. Adding Calico networking

Add the containers to the Calico network.

On calico-01 run:

    sudo calicoctl container add workload-F fd80:24e2:f998:72d6::1

On calico-02 run::

    sudo calicoctl container add workload-G fd80:24e2:f998:72d6::2
    
Now create a security profile and set the profile on the two containers.

On either calico host:

    calicoctl profile add PROF_F_G

On calico-01:

    calicoctl container workload-F profile append PROF_F_G

On calico-02:

    calicoctl container workload-G profile append PROF_F_G

## 6. Validation

Now you can ping between the two containers using their IPv6 addresses.

On calico-02:

    docker exec workload-G ping6 -c 4 fd80:24e2:f998:72d6::1
[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/calico-with-docker/without-docker-networking/IPv6.md?pixel)](https://github.com/igrigorik/ga-beacon)
