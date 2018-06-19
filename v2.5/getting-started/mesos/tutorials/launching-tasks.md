---
title: Launching Tasks
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/mesos/tutorials/launching-tasks'
---

The following information describes how to launch Calico networked tasks in Mesos
using sample Marathon application definitions.

### Unified Containerizer

Launch a Unified Containerizer task onto a Calico network by setting
 `networkName` to the name of your Calico network. Its value should match the `"name"`
 field of the `calico.conf` you configured when [Installing Calico for Mesos](../installation/integration)

```json
{
  "id": "unified-task",
  "cmd": "/usr/sbin/ip addr show && sleep 1000",
  "ipAddress": {
      "networkName": "calico"
  }
}
```

>Be sure to replace `/usr/sbin/ip` with the correct path to your IP binary.

The task's stdout output should show a Calico IP from the default Calico pool of `192.168.0.0/16`.

### Docker Containerizer

To launch a Docker Containerizer task, first create a Docker Network to launch it on:

```
docker network create --driver=calico --ipam-driver=calico-ipam calico-nginx
```

Then in your marathon application definition,
set `network` to `USER`, and set `networkName` to the name of your Calico network:

```json
{
  "id": "docker-task",
  "container": {
    "type": "DOCKER",
    "docker": {
      "image": "nginx",
      "network": "USER"
    }
  },
  "ipAddress": {
      "networkName": "calico-nginx"
  }
}
```

## Enabling Health Checks

Marathon supports Health Checks for IP per container applications. Health Checks
should specify a `port` (instead of the `portIndex` field which is commonly used
for port-mapped applications).

For the Health Check to succeed, the following conditions must be met:

1. The host running Marathon will need routes to Calico tasks. If you are running
Marathon as a Mesos task, and have already installed Calico on each Agent,
you have met this requirement.

2. Calico Networking Policy should permit the health check from Marathon to the
target application.

The following sample application launches a nginx webserver with healtchecks:

```json
{
  "id": "nginx",
  "container": {
    "type": "DOCKER",
    "docker": {
      "image": "nginx",
      "network": "USER"
    }
  },
  "ipAddress": {
      "networkName": "calico"
  },
  "healthChecks": [{
      "protocol": "HTTP",
      "path": "/",
      "port": 80
  }]
}
```

The following Calico Profile yaml will allow the health check from an instance
of Marathon running at 172.24.197.101:

```yaml
cat << EOF | calicoctl apply -f -
apiVersion: v1
kind: profile
metadata:
  name: calico
spec:
  ingress:
  - action: allow
    protocol: tcp
    source:
      nets:
      - 172.24.197.101/32
    destination:
      ports: [80]
EOF
```

## Next

[Connecting to Tasks](connecting-tasks)
