---
title: Quickstart with Docker-Compose - Calico for Mesos CNI
---
This directory includes files for running a docker-compose demo of Calico for Mesos CNI.

Once running, this demo will run `etcd`, `mesos-master`, `marathon`, and `zookeeper`
in their own separate containers. It will also run a `agent` with its own
isolated docker-in-docker environment, with calico-node running inside.

We've simplified the commands into a Makefile for ease of use. If running the docker-compose
commands directly, be sure to pass the `-p mesoscni` flag.

## Prerequisites
- Linux host (we recommend Ubuntu 14.04), capable of volume mounting `/var/lib/modules`
- docker-compose

## Getting Started

### 1. Clone the Repository

```shell
git clone https://github.com/projectcalico/calico.git
cd calico/{{page.version}}/mesos/demos/cni/
```

### 2. Download and Build Images

```shell
make images
```

### 3. Start the Cluster

```shell
make cluster
```

### 4. Next Steps
Once your cluster has launched, access the Mesos-Master UI at `localhost:5050`, and Marathon UI at `localhost:8080`.

You can quickly launch a calico-networked task which runs `ifconfig` by running `make test-cni`:

```shell
$ make test-cni
docker exec mesoscni_mesosmaster_1 mesos-execute --containerizer=mesos --docker_image=busybox --name=cni --master=localhost:5050 --networks=calico-net-1 --command="ifconfig"
I0711 22:00:55.867799    66 logging.cpp:193] INFO level logging started!
I0711 22:00:55.867971    66 scheduler.cpp:187] Version: 1.0.0
I0711 22:00:55.868762    72 scheduler.cpp:471] New master detected at master@127.0.0.1:5050
Subscribed with ID '1b90fee7-ed10-439e-aabf-d3778b39749c-0004'
Submitted task 'cni' to agent '1b90fee7-ed10-439e-aabf-d3778b39749c-S0'
Received status update TASK_RUNNING for task 'cni'
  source: SOURCE_EXECUTOR
Received status update TASK_FINISHED for task 'cni'
  message: 'Command exited with status 0'
  source: SOURCE_EXECUTOR
```

Check that your task was networked by calico by viewing its `stdout` log in the Mesos Master UI. If you see that eth0 has been assigned an IP from the default calico pool of 192.168.0.0/16, then it worked!

```shell
Received SUBSCRIBED event
Subscribed executor on 172.19.0.7
Received LAUNCH event
Starting task cni
Forked command at 1762
sh -c 'ifconfig'
eth0      Link encap:Ethernet  HWaddr 1E:49:82:B4:C1:F8
          inet addr:192.168.227.194  Bcast:0.0.0.0  Mask:255.255.255.255
          inet6 addr: fe80::1c49:82ff:feb4:c1f8/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:11 errors:0 dropped:0 overruns:0 frame:0
          TX packets:11 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:2476 (2.4 KiB)  TX bytes:1558 (1.5 KiB)

Command exited with status 0 (pid: 1762)
```

For more information on using Calico with Mesos CNI, see the [Calico-CNI for Mesos Unified Containerizer Usage Guide]({{site.baseurl}}/{{page.version}}/getting-started/mesos/tutorials/unified).
