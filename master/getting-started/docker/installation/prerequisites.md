---
title:  Calico-Docker Prerequisites
---

Calico networking for docker containers requires that all docker hosts
have IP connectivity between them.

You will need at least one server (bare metal or VM) with a modern 64-bit Linux OS
and IP connectivity between them.

### etcd

You will also need an etcd cluster accessible from each host which Calico
uses for coordinating state between the nodes. See the [etcd documentation][etcd]
for details on setting up a cluster.

### Docker with Multi-host Networking

Each server should have Docker 1.9 or greater installed.

Each docker daemon should be configured with a central cluster-store.

Follow the [instructions for installing Docker][docker].  A version of 1.9 or
greater is required.

To use Calico as a Docker network plugin, the Docker daemon
needs to run specifying a cluster store.  If using etcd as a cluster store,
configure the `cluster-store` on the Docker daemon to `etcd://<ETCD_IP>:<ETCD_PORT>`,
replacing `<ETCD IP>` and <ETCD_PORT> with the appropriate address and client
port for your etcd cluster.

> For Docker 1.10+, you can use the [daemon configuration file][daemon-config-file],
> or for 1.9 see the appropriate 'Configuring Docker' section in [configuring docker][configuring-docker-1.9].


[etcd]: https://coreos.com/etcd/docs/latest/
[docker]: https://docs.docker.com/engine/installation/
[daemon-config-file]: https://docs.docker.com/engine/reference/commandline/dockerd/#/daemon-configuration-file
[configuring-docker-1.9]: https://docs.docker.com/v1.9/engine/articles/configuring/
