---
title:  Preparing the environment for Calico as a Docker network plugin
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/docker/installation/manual'
---

The worked example in the _Calico as a Docker network plugin tutorial_ is run
on two Linux servers that have a number of installation requirements.

This tutorial describes how to manually configure a working environment for
the example.

## Requirements

You will need 2 servers (bare metal or VMs) with a  modern 64-bit Linux OS
and IP connectivity between them.

We recommend configuring the hosts with the hostname `calico-01` and
`calico-02`.  The worked example will refer to these hostnames.

They must have the following software installed:

- Docker 1.9 or greater (details below)
- `ip_set`, `iptables`, and `ip6tables` kernel modules.
-  The `calicoctl` binary in your path (see below)

You will also need an etcd cluster which Calico uses for coordinating state
between the nodes.  This may installed on one or both of the two servers for
the worked example.  See the [etcd documentation][etcd] for details on setting
up a cluster.

> NOTE: If you are running etcd with SSL/TLS, see the [Etcd Secure Cluster]({{site.baseurl}}/{{page.version}}/reference/advanced/etcd-secure)
> documentation.

### Docker (with multi-host networking)

Follow the instructions for installing [Docker][docker].  A version of 1.9 or
greater is required.

To use Calico as a Docker network plugin, the Docker daemon
needs to run specifying a cluster store.  If using etcd as a cluster store,
configure the `cluster-store` on the Docker daemon to `etcd://<ETCD_IP>:<ETCD_PORT>`,
replacing `<ETCD IP>` and <ETCD_PORT> with the appropriate address and client
port for your etcd cluster.

> For Docker 1.10+, you can use the [daemon configuration file][daemon-config-file],
> or for 1.9 see the appropriate 'Configuring Docker' section in [configuring docker][configuring-docker-1.9].

#### Docker permissions

Running Docker is much easier if your user has permissions to run Docker
commands. If your distro didn't set this permissions as part of the install,
you can usually enable this by adding your user to the `docker` group and
restarting your terminal.

    sudo usermod -aG docker <your_username>

If you prefer not to do this you can still run the demo but remember to run
`docker` using `sudo`.

### Getting calicoctl Binary

Get the calicoctl binary onto each host.

	wget https://github.com/projectcalico/calico-containers/releases/download/v0.22.0/calicoctl
	chmod +x calicoctl

This binary should be placed in your `$PATH` so it can be run from any
directory.

### Preload the Calico docker images (optional)

You can optionally preload the Calico Docker image to avoid the delay when you
run `calicoctl node` the first time.  Select the appropriate versions of the
`calico/node` and `calico/node-libnetwork` as required by the version of
calicoctl:

    docker pull calico/node:v0.22.0
    docker pull calico/node-libnetwork:v0.9.0

### Final checks

Verify the hostnames.  If they don't match the recommended names above then
you'll need to adjust the tutorial instructions accordingly.

Check that the hosts have IP addresses assigned, and that your hosts can ping
one another.

Check that you are running with a suitable version of Docker.

    docker version

It should indicate a version of 1.9 or greater.

You should also verify each host can access etcd.  The following will return
the current etcd version if etcd is available.

    curl -L http://127.0.0.1:2379/version

## Continue with the worked example

With the environment set up, you can run through the remainder of the worked
example in the [Calico as a Docker network plugin tutorial]({{site.baseurl}}/{{page.version}}/getting-started/docker/tutorials/basic).

[etcd]: https://coreos.com/etcd/docs/latest/
[docker]: https://docs.docker.com/engine/installation/
[daemon-config-file]: https://docs.docker.com/engine/reference/commandline/dockerd/#/daemon-configuration-file
[configuring-docker-1.9]: https://docs.docker.com/v1.9/engine/articles/configuring/

