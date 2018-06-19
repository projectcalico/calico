---
title:  Requirements
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/docker/installation/requirements'
---

The following information details basic prerequisites that must be met
in order for {{site.prodname}} to function properly with Docker.

### Host IP Connectivity

As with all {{site.prodname}} clusters, all hosts should have IP connectivity between them.

### etcd

You will also need an etcd cluster accessible from each host which {{site.prodname}}
uses for coordinating state between the nodes. See the [etcd documentation][etcd]
for details on setting up a cluster.

### Docker with Multi-host Networking

Each server should have Docker 1.9 or greater installed.
Follow the [instructions for installing Docker][docker].

To use {{site.prodname}} as a Docker network plugin, the Docker daemon must be configured
with a cluster store.  If using etcd as a cluster store,
configure the `cluster-store` on the Docker daemon to `etcd://<ETCD_IP>:<ETCD_PORT>`,
replacing `<ETCD_IP>` and `<ETCD_PORT>` with the appropriate address and client
port for your etcd cluster.  If your etcd is configured with TLS then you must
also [configure the Docker daemon][daemon-cert-config] with the correct
certificates to allow access.

> **Note**: For Docker 1.10+, you can use the [daemon configuration file][daemon-config-file],
> or for 1.9 see the appropriate 'Configuring Docker' section in 
> [configuring docker][configuring-docker-1.9].
{: .alert .alert-info}


## Next Steps

With etcd running and Docker configured, you are ready to
[install {{site.prodname}}](manual).


[etcd]: https://coreos.com/etcd/docs/latest/
[docker]: https://docs.docker.com/engine/installation/
[daemon-config-file]: https://docs.docker.com/engine/reference/commandline/dockerd/#/daemon-configuration-file
[daemon-cert-config]: https://docs.docker.com/engine/reference/commandline/dockerd/#nodes-discovery
[configuring-docker-1.9]: https://docs.docker.com/v1.9/engine/articles/configuring/
