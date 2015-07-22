# Manual Cluster Setup

This document describes requirements and best practices for setting up a cluster to network containers using Calico Docker.

## Requirements

Two or more servers (bare metal or VMs) with a modern 64-bit Linux OS, each with a unique hostname.

They must have the following software installed.
 * Docker v1.8 or greater: [Experimental Docker](https://experimental.docker.com)
 * etcd installed and available on each node: [etcd Documentation](https://coreos.com/etcd/docs/latest/)
 * Consul installed and available on each node: [Consul Documentation](https://www.consul.io/docs/index.html)
   * Consul is required for Docker Networking.  etcd support is planned, but currently broken.
   * Do not run Consul in a Docker container; it must be available when the Docker daemon starts.
 * `ipset`, `iptables`, and `ip6tables` kernel modules.

## Getting a Docker 1.8 Experimental Binary

An experimental Docker binary is usually not available via your Linux distribution's package repos, so you will need to install it directly.

We recommend that you download your Docker binary from [the release page](https://github.com/Metaswitch/calico-docker/releases) of the Calico version you are using, rather than experimental.docker.com, since we will have had a chance to check it functions with Calico.

For example: 

    sudo wget -O $(which docker) https://github.com/Metaswitch/calico-docker/releases/download/v0.5.2/docker

## Docker libnetwork setup

Once Consul is up and running, you'll need to modify your Docker daemons' startup arguments to get them to use the Consul data store for multi-host networking.

For `systemd` init systems, like Ubuntu 15+ or RedHat/Centos, the Docker service file is usually `/usr/lib/systemd/system/docker.service`.

For `upstart` init systems, like Ubuntu 14.04 LTS, the file is usually `/etc/default/docker`.

Edit your file to add `--kv-store=consul:<consul_ip>:8500` to the Docker daemon options.  (Where `<consul_ip>` is the IP or hostname where you have Consul runnning.)

Restart Docker on each host.

## Docker permissions

The [example script][example-commands] assumes that your ordinary user account has permission to run Docker images without `sudo`.  If you haven't done so, you can enable this by adding your user to the `docker` group and restarting your terminal.

    sudo usermod -aG docker <your_username>

## Getting Calico Binaries

Get the calico binary onto each host.  You can download a specific [release](https://github.com/Metaswitch/calico-docker/releases/) from github.  For example, to retrieve the latest v0.5.2 release, on each host run

	wget https://github.com/Metaswitch/calico-docker/releases/download/v0.5.2/calicoctl
	chmod +x calicoctl

Finally, you can optionally preload the `calico/node` Docker image, which is the agent that runs on each compute host.  This will make starting Calico on each node more responsive the first time you run it.  Select the same version of the `calico/node` Docker image as the version of `calicoctl` you downloaded above.  For example, to pull the latest released version

    docker pull calico/node:v0.5.2
    
## IP-in-IP setup for public clouds
If you are setting up a Calico cluster in a public cloud where you do not have control over the physical interconnect fabric, you will need to enable IP-in-IP.  There specific guides for the following cloud providers

  * [Amazon Web Services](AWS.md)
  * [Digital Ocean](DigitalOcean.md)
  * [Google Compute Engine](GCE.md)

If your provider is not listed, then set up your cluster as above, but before starting Calico services, run the following command to enable IP-in-IP.

    ./calicoctl pool add 192.168.0.0/16 --ipip

## Final checks

Note the hostnames and IP addresses assigned to your servers.  You will need these when you start Calico services.

Verify that your hosts can ping one another.

You should also verify each host can access etcd.  The following will return an error if etcd is not available.

    etcdctl ls /
    
Verify that your Docker daemons are back up after restarting them with the `--kv` flag above.

    docker version

You are now ready to run the [example commands][example-commands].

[example-commands]: ./GettingStarted.md#calico-services

