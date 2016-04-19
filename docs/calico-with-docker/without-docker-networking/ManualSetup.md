<!--- master only -->
> ![warning](../../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Preparing the environment for Calico without Docker networking

The worked example in the _Calico without Docker networking tutorial_ is run on
two Linux servers that have a number of installation requirements.

This tutorial describes how to manually configure a working environment for
the example.

# Manual Setup

## Requirements

You will need 2 servers (bare metal or VMs) with a  modern 64-bit Linux OS 
and IP connectivity between them.

We recommend configuring the hosts with the hostname `calico-01` and 
`calico-02`.  The tutorial will refer to these hostnames.

They must have the following software installed:

- Docker v1.6 or greater: [Docker][docker]
- etcd installed and available on each node: [etcd documentation][etcd]
- `ipset`, `iptables`, and `ip6tables` kernel modules.
- The `calicoctl` binary in your path (see below)

You will also need an etcd cluster which Calico uses for coordinating state
between the nodes.  This may installed on one or both of the two servers for
the worked example.  See the [etcd documentation][etcd] for details on setting
up a cluster.

> NOTE: If you are running etcd with SSL/TLS, see the [Etcd Secure Cluster](../../EtcdSecureCluster.md)
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

	wget http://www.projectcalico.org/builds/calicoctl
	chmod +x calicoctl
	
This binary should be placed in your `$PATH` so it can be run from any
directory.

### Preload the Calico docker image (optional)

You can optionally preload the Calico Docker image to avoid the delay when you 
run `calicoctl node` the first time.  Select the appropriate versions of the 
`calico/node` as required by the version of calicoctl:

    docker pull calico/node:latest

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
example in the [Calico without Docker networking tutorial](README.md).

[etcd]: https://coreos.com/etcd/docs/latest/
[calico-releases]: https://github.com/projectcalico/calico-containers/releases/
[docker]: http://www.docker.com
[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/calico-with-docker/without-docker-networking/ManualSetup.md?pixel)](https://github.com/igrigorik/ga-beacon)
