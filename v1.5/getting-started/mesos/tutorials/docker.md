---
title: Calico-Mesos Usage Guide with the Docker Containerizer
canonical_url: 'https://docs.projectcalico.org/v2.1/getting-started/mesos/tutorials/docker'
---

This guide shows how to use Marathon to start
Calico networked containers using the Docker
Containerizer in Mesos.  This guide covers:
-  Creating and configuring a Docker Network with Calico
-  Launching a Docker Task in Marathon on the created Calico Network

## Prerequisites
This guide assumes you have a running Mesos Cluster that meets the following specifications:

- etcd
- Marathon
- Mesos Master
- 1 or more Mesos Agent(s) with:
  - Docker Containerizer enabled in Mesos
  - Docker 1.9+ installed with a configured cluster store
  - calico-node and calico-libnetwork services running

To quickly generate a cluster that meets all of these requirements, follow the [Calico Mesos Vagrant guide]({{site.baseurl}}/{{page.version}}/getting-started/mesos/vagrant) before continuing.

For info on upgrading an Agent to meet the above requirements and be ready for Calico, see the [Manual Install Docker Containerizer Guide]({{site.baseurl}}/{{page.version}}/getting-started/mesos/installation/docker)


## Creating a Docker network and managing network policy

Before we can start launching tasks, we must first create a docker network with Calico.

With Calico, a Docker network represents a logical set of rules that defines the
allowed traffic in and out of containers assigned to that network.  The rules
are encapsulated in a Calico "profile".  Each Docker network is assigned its
own Calico profile.

Run the following command on any agent to create a Docker network with Calico:

```shell
docker network create --driver=calico --ipam-driver=calico my-calico-net
```

#### View Network Policy

You can use the `calicoctl profile <profile> rule show` to display the
rules in the profile associated with the `my-calico-net` network.

The network name can be supplied as the profile name and the `calicoctl` tool
will look up the profile associated with that network.

Be sure to replace `<etcd-ip:port>` with the address and port at which etcd
is listening.

```shell
$ export ETCD_AUTHORITY=<etcd-ip:port>
$ calicoctl profile my-calico-net rule show
Inbound rules:
   1 allow from tag my-calico-net
Outbound rules:
   1 allow
```

The default rules allow all outbound traffic and accept inbound
traffic only from containers attached the "my-calico-net" network.

> Note that when managing profiles created by the Calico network driver, the
> profile tag and network name can be regarded as the same thing.

For more information no how to configure your Calico profiles, see [Configuring Advanced Network Policy Guide]({{site.baseurl}}/{{page.version}}/getting-started/docker/tutorials/advanced-policy#configuring-the-network-policy).

## Launching Containers
With your networks configured, it is trivial to launch a calico-networked Docker container using the standard Marathon API.

#### Marathon v1.2.0+
In your Marathon application definition, set `container.docker.network` to `USER`, and specify which network the task should join in `ipAddress.networkName`:

```json
{
  "id": "my-docker-task",
  "cpus": 0.1,
  "mem": 64.0,
  "container": {
      "type": "DOCKER",
      "docker": {
          "network": "USER",
          "image": "nginx"
      }
  },
  "ipAddress": {
      "networkName": "my-calico-net"
  },
  "healthChecks": [{
      "protocol": "HTTP",
      "path": "/",
      "port": 80,
      "gracePeriodSeconds": 300,
      "intervalSeconds": 60,
      "timeoutSeconds": 20,
      "maxConsecutiveFailures": 3
  }]
}
```

#### Marathon <v1.2.0
Though "USER" is not a valid network type in Marathon <v1.2.0, you can still launch applications on a Calico network in earlier versions of Marathon, by passing the network name as an arbitrary docker parameter:

```json
{
  "id": "my-docker-task",
  "cpus": 0.1,
  "mem": 64.0,
  "container": {
      "type": "DOCKER",
      "docker": {
          "image": "nginx",
          "parameters": [{"key": "net", "value": "my-calico-net"}]
      }
  },
  "ipAddress": {},
  "healthChecks": [{
      "protocol": "HTTP",
      "path": "/",
      "port": 80,
      "gracePeriodSeconds": 300,
      "intervalSeconds": 60,
      "timeoutSeconds": 20,
      "maxConsecutiveFailures": 3
    }]
}
```

This application will start an nginx webserver accessible via its Calico IP.

You can launch this task by pasting the JSON into the "JSON Mode" editor in the Marathon UI, or by calling into the Marathon REST API
using the command line as follows:

	curl -X POST -H "Content-Type: application/json" http://<MARATHON_IP>:8080/v2/apps -d @app.json

Once launched, you will see the task's Calico-assigned IP address in the Marathon UI application view.
