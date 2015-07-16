# Manual Cluster Setup

This document describes requirements and best practices for setting up a cluster to network containers using Calico Docker.

## Requirements

2 servers (bare metal or VMs) with a modern 64-bit Linux OS, and Layer-2 network (Ethernet) connectivity between them.

They must have the following software installed.
 * Docker v1.8 or greater: [Experimental Docker](https://experimental.docker.com)
 * etcd installed and available on each node: [etcd Documentation](https://coreos.com/etcd/docs/2.0.8/)
 * `ipset`, `iptables`, and `ip6tables` kernel modules.

## Best Practices

### CoreOS
A prepackaged version of CoreOS with the required version of Docker is not yet available.  Calico uses the [libnetwork plugin](https://github.com/docker/libnetwork) which is currently only available in Experimental Docker v1.8.

If CoreOS is your distribution, we recommend viewing an earlier version of our [Manual Cluster Setup](https://github.com/Metaswitch/calico-docker/blob/powerstrip-archive/docs/ManualClusterSetup.md) which uses the Powerstrip plugin.

### Ubuntu
The Ubuntu-managed Docker package is out of date and will not work with `calicoctl`.  We recommend you follow the instructions in the comments of the [Experimental Docker Website](https://experimental.docker.com) to get an up-to-date Docker install.

### Final checks

Note the hostnames and IP addresses assigned to your servers.  You will need these when you start Calico services.

Verify that your hosts can ping one another.

You should also verify each host can access etcd.  The following will return an error if etcd is not available.

    etcdctl ls /

## Docker permissions

The [example script][example-commands] assumes that your ordinary user account has permission to run Docker images without `sudo`.  If you haven't done so, you can enable this by adding your user to the `docker` group and restarting your terminal.

    sudo usermod -aG docker <your_username>

## Getting Calico Binaries

Get the calico binary onto each host.  You can download a specific [release](https://github.com/Metaswitch/calico-docker/releases/) from github.  For example, to retrieve the latest v0.5.1 release, on each host run

	wget https://github.com/Metaswitch/calico-docker/releases/download/v0.5.1/calicoctl
	chmod +x calicoctl

Finally, you can optionally preload the Calico Docker image.  This will make the Calico container creation more responsive the first time you run it.  Select the same version of the Calico Docker image as you selected above.  For example, to pull the latest released version

    docker pull calico/node:v0.5.1

You are now ready to run the [example commands][example-commands].

[example-commands]: ./GettingStarted.md#calico-services
