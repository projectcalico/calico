---
title: Launching Tasks
redirect_from: latest/getting-started/mesos/tutorials/launching-tasks
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/mesos/tutorials/launching-tasks'
---

The following information describes how to launch {{site.prodname}} networked tasks in Mesos
using sample Marathon application definitions.

### Unified Containerizer

Launch a Unified Containerizer task onto a {{site.prodname}} network by setting
 `networkName` to the name of your {{site.prodname}} network. Its value should match the `"name"`
 field of the `calico.conf` you configured when [Installing {{site.prodname}} for Mesos](../installation/integration)

```json
{
  "id": "unified-task",
  "cmd": "/usr/sbin/ip addr show && sleep 1000",
  "ipAddress": {
      "networkName": "calico"
  }
}
```

> **Note**: Replace `/usr/sbin/ip` with the correct path to your IP binary.
{: .alert .alert-info}

The task's stdout output should show a {{site.prodname}} IP from the default {{site.prodname}} pool of `192.168.0.0/16`.

### Docker Containerizer

To launch a Docker Containerizer task, first create a Docker Network to launch it on:

```
docker network create --driver=calico --ipam-driver=calico-ipam calico-nginx
```

Then in your marathon application definition,
set `network` to `USER`, and set `networkName` to the name of your {{site.prodname}} network:

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

1. The host running Marathon will need routes to {{site.prodname}} tasks. If you are running
Marathon as a Mesos task, and have already installed {{site.prodname}} on each Agent,
you have met this requirement.

2. {{site.prodname}} Networking Policy should permit the health check from Marathon to the
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

The following {{site.prodname}} Profile yaml will allow the health check from an instance
of Marathon running at 172.24.197.101:

```yaml
cat << EOF | calicoctl apply -f -
apiVersion: projectcalico.org/v3
kind: Profile
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
