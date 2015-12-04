<!--- master only -->
> ![warning](../../images/warning.png) This document applies to the HEAD of the calico-docker source tree.
>
> View the calico-docker documentation for the latest release [here](https://github.com/projectcalico/calico-docker/blob/v0.12.0/README.md).
<!--- else
> You are viewing the calico-docker documentation for release **release**.
<!--- end of master only -->

# Preparing the environment for Docker default networking

The basic Calico demonstration is run on two Linux servers that have a number
of installation requirements.

This document describes how to get a working environment for the demonstration.

Follow instructions using either the [Automated setup](#automated-setup) for
fast setup in a virtualized environment, or [Manual Setup](#manual-setup) if,
for example, you are installing on bare metal servers or would like to
understand the process in more detail.

Once you have the environment set up, you can run through the 
[demonstration](Demonstration.md).

## Automated setup

The worked examples below allow you to quickly set up a virtualized environment
using Vagrant or a cloud service - be sure to follow the appropriate instructions
for using the default Docker networking.

- [Vagrant install with CoreOS](../VagrantCoreOS.md)
- [Vagrant install with Ubuntu](../VagrantUbuntu.md)
- [Amazon Web Services (AWS)](../AWS.md)
- [Google Compute Engine (GCE)](../GCE.md)
- [DigitalOcean](../DigitalOcean.md)

# Manual Setup

## Summary

The two Linux servers require a recent version of Linux with a few network 
network related kernel modules to be loaded. The easiest way to ensure this and
that the servers meet the requirements is to run `calicoctl checksystem`

The servers also need:
- Docker to be running - since the Calico agent is packaged as a Docker 
container.
- An Etcd cluster - which Calico uses for coordinating state between the nodes.
- The `calicoctl` to be placed in the `$PATH`.

## Requirements

For the demonstration, you just need 2 servers (bare metal or VMs) with a 
modern 64-bit Linux OS and IP connectivity between them.

We recommend configuring the hosts with the hostname `calico-01` and 
`calico-02`.  The demonstration will refer to these hostnames.

They must have the following software installed:
- Docker v1.6 or greater: [Docker][docker]
- etcd installed and available on each node: [etcd documentation][etcd]
- `ipset`, `iptables`, and `ip6tables` kernel modules.

> NOTE: If you are running etcd with SSL/TLS, see the (Etcd Secure Cluster)[../../EtcdSecureCluster.md]
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
you'll need to adjust the demonstration instructions accordingly.

Check that the hosts have IP addresses assigned, and that your hosts can ping
one another.

You should also verify each host can access etcd.  The following will return 
the current etcd version if etcd is available.

    curl -L http://127.0.0.1:2379/version
    
[etcd]: https://coreos.com/etcd/docs/latest/
[calico-releases]: https://github.com/projectcalico/calico-docker/releases/
[docker]: http://www.docker.com
[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-docker/docs/getting-started/default-networking/EnvironmentSetup.md?pixel)](https://github.com/igrigorik/ga-beacon)
