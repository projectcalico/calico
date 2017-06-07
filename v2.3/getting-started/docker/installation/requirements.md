---
title:  Requirements
---

The following information details basic prerequisites that must be met
in order for Calico to function properly with Docker.

### Host IP Connectivity

As with all Calico clusters, all hosts should have IP connectivity between them.

### etcd

You will also need an etcd cluster accessible from each host which Calico
uses for coordinating state between the nodes. See the [etcd documentation][etcd]
for details on setting up a cluster.

### Docker with Multi-host Networking

Each server should have Docker 1.9 or greater installed.
Follow the [instructions for installing Docker][docker].

To use Calico as a Docker network plugin, the Docker daemon must be configured
with a cluster store.  If using etcd as a cluster store,
configure the `cluster-store` on the Docker daemon to `etcd://<ETCD_IP>:<ETCD_PORT>`,
replacing `<ETCD IP>` and <ETCD_PORT> with the appropriate address and client
port for your etcd cluster.

> For Docker 1.10+, you can use the [daemon configuration file][daemon-config-file],
> or for 1.9 see the appropriate 'Configuring Docker' section in [configuring docker][configuring-docker-1.9].

## Next Steps

With etcd running and Docker configured, you are ready to
[install Calico](manual).


[etcd]: https://coreos.com/etcd/docs/latest/
[docker]: https://docs.docker.com/engine/installation/
[daemon-config-file]: https://docs.docker.com/engine/reference/commandline/dockerd/#/daemon-configuration-file
[configuring-docker-1.9]: https://docs.docker.com/v1.9/engine/articles/configuring/
