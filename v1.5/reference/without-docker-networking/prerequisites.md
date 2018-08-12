---
title: Preparing the environment for Calico without Docker networking
sitemap: false 
---

The worked example in the _Calico without Docker networking tutorial_ is run on
two Linux servers that have a number of installation requirements.

This tutorial describes how to manually configure a working environment for
the example.

## Requirements

You will need 2 hosts (bare metal or VMs) with a modern 64-bit Linux OS and IP
connectivity between them.  The servers must not run any software that tries to
manage or interfere with new interfaces or related config (for example routes,
iptables, ipsets or interface state), as that is likely to conflict with
Calico's programming and lead to loss of endpoint connectivity.  We recommend
using 'server' OS installs rather than 'desktop'.  (For NetworkManager in
particular, please see also [Troubleshooting]({{site.baseurl}}/{{page.version}}/usage/troubleshooting).)

The hosts must have different hostnames.  We recommend `calico-01` and
`calico-02`, and the tutorial will use those names.

Each node must have the following software installed:

- Docker v1.6 or greater: [Docker][docker]
- etcd: [etcd documentation][etcd]
- `ipset`, `iptables`, and `ip6tables` kernel modules.
- The `calicoctl` binary in your path (see below)

Calico uses an etcd cluster for coordinating state between the nodes.  See the
[etcd documentation][etcd] for details on setting up an etcd cluster.

> NOTE: If you are running etcd with SSL/TLS, see the [Etcd Secure Cluster]({{site.baseurl}}/{{page.version}}/reference/advanced/etcd-secure)
> page.

### Docker permissions

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

### Preload the Calico docker image (optional)

You can optionally preload the Calico Docker image to avoid the delay when you
run `calicoctl node` the first time.  Select the appropriate versions of the
`calico/node` as required by the version of calicoctl:

    docker pull calico/node:v0.22.0

## Final checks

Verify the hostnames.  If they don't match the recommended names above then
you'll need to adjust the tutorial instructions accordingly.

Check that the hosts have IP addresses assigned, and that your hosts can ping
one another.

You should also verify each host can access etcd.  The following will return
the current etcd version if etcd is available.

    curl -L http://127.0.0.1:2379/version

## Continue with the worked example

With the environment set up, you can run through the remainder of the worked
example in the [Calico without Docker networking tutorial]({{site.baseurl}}/{{page.version}}/reference/without-docker-networking/installation).

[etcd]: https://coreos.com/etcd/docs/latest/
[calico-releases]: https://github.com/projectcalico/calico-containers/releases/
[docker]: http://www.docker.com
