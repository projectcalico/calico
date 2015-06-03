# Manual Cluster Setup

This document describes requirements and best practices for setting up a cluster for trying the Calico Docker Prototype.

## Requirements

2 servers (bare metal or VMs) with a modern 64-bit Linux OS, and Layer-2 network (Ethernet) connectivity between them.

They must have the following software installed.
 * Docker v1.4 or greater: [Installing Docker](https://docs.docker.com/installation/)
 * etcd installed and available on each node: [etcd Documentation](https://coreos.com/etcd/docs/2.0.8/)
 * `ipset`, `iptables`, and `ip6tables` kernel modules.

## Best Practices

### CoreOS
If CoreOS is your distribution, we recommend using cloud-config to bootstrap your etcd cluster.  [CoreOS Cluster Discovery](https://coreos.com/docs/cluster-management/setup/cluster-discovery/) is a good place to start.

### Ubuntu
The Ubuntu-managed Docker package is out of date and will not work with `calicoctl`.  We recommend you follow the instructions at the [Docker Website](https://docs.docker.com/installation/) to get an up-to-date Docker install.

### Final checks

Note the hostnames and IP addresses assigned to your servers.  You will need these when you start Calico services.

Verify that your hosts can ping one another.

You should also verify each host can access etcd.  The following will return an error if etcd is not available.

    etcdctl ls /

## Docker permissions

The [example script][example-commands] assumes that your ordinary user account has permission to run Docker images without `sudo`.  If you haven't done so, you can enable this by adding your user to the `docker` group and restarting your terminal.

    sudo usermod -aG docker <your_username>

## Getting Calico Binaries

Get the calico binary onto each host. It's usually safe to just grab the latest [beta](http://projectcalico.org/latest/calicoctl).  On each host run

    wget http://projectcalico.org/latest/calicoctl
	chmod +x calicoctl

Note that projectcalico.org is not an HA repository, so using this download URL is not recommended for any automated production installation process.  Alternatively, you can download a specific [release](https://github.com/Metaswitch/calico-docker/releases/) from github.  For example, to retrieve the v0.4.3 release, on each host run

	wget https://github.com/Metaswitch/calico-docker/releases/download/v0.4.3/calicoctl
	chmod +x calicoctl

Finally, preload the Calico Docker image.  This will make the demo more responsive the first time you run it.  Select the same version of the Calico Docker image as you selected for the calico binary.  For example, to pull the latest beta

    docker pull calico/node:latest

or to pull the latest released version

    docker pull calico/node:v0.4.3

You are now ready to run the [example commands][example-commands].

[example-commands]: ./GettingStarted.md#calico-services
