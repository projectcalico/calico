---
title: Calico-Mesos Usage Guide for the Docker Containerizer
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
  - calico-node service running

To generate a cluster that meets all of these requirements, follow the [Calico Mesos Vagrant guide]({{site.baseurl}}/{{page.version}}/getting-started/mesos/vagrant) before continuing.

For info on upgrading an Agent to meet the above requirements and be ready for Calico, see the [Integration Guide]({{site.baseurl}}/{{page.version}}/getting-started/mesos/installation/integration)


## Creating a Docker network and managing network policy

Before we can start launching tasks, we must first create a docker network with Calico.

Run the following command on any agent to create a Docker network with Calico:

```shell
docker network create --driver=calico --ipam-driver=calico-ipam my-calico-net
```

By default, Calico will apply policy to allow full communication between endpoints
within the network, and no  communication from other networks.  However,
Calico allows richly configurable policy, which can be managed using the `calicoctl`
command line tool.

Please refer to
[Security using Calico Profiles and Policy]({{site.baseurl}}/{{page.version}}/getting-started/docker/tutorials/security-using-calico-profiles-and-policy)
in the Docker section for details on configuring advanced policy when using
Calico with Docker networks.

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
