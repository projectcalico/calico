---
title:  Manual Installation of Calico with rkt
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/rkt/installation/manual'
---

This tutorial describes how to manually configure a working environment for
a cluster of Calico-rkt enabled nodes.

* TOC
{:toc}

## System requirements

- A cluster of bare metal servers or VMs (nodes) with a modern 64-bit Linux OS and IP connectivity
  between them.
- A recent version of [`rkt`](https://github.com/coreos/rkt/releases/latest) installed on each node in the cluster.  We recommend
  version > 1.20.0 as this is contains important fixes that prevent leaking IP addresses
  when containers are deleted.
- An [`etcd`](https://coreos.com/etcd/docs/latest/) cluster accessible by all nodes in the cluster

## About the Calico Components

There are three components of a Calico / rkt integration.

- The Calico per-node rkt container, [calico/node](https://quay.io/repository/calico/node?tab=tags)
- The [`calicoctl`](https://github.com/projectcalico/calicoctl/releases) command line tool.
- The [cni-plugin](https://github.com/projectcalico/cni-plugin/releases) network plugin binaries.
  - This is the combination of two binary executables and a configuration file.

The `calico/node` docker container must be run on each node in your cluster.  It contains
the BGP agent which provides Calico routing, and the Felix agent which programs network policy
rules.

The `calicoctl` binary is a command line utility that can be used to manage network policy
for your rkt containers, and can be used to monitor the status of your Calico services.

The Calico CNI network plugin binaries are a combination of two binary executables.
These binaries are invoked from the rkt container lifecycle hooks on each node to configure
the container interfaces,  manage IP addresses and enable Calico policy on the containers.

## Installing `calico/node`

#### Prepare host directory structure

The `calicoctl` binary uses certain known directories for service diagnostics and
status discovery.  In addition, this tutorial assumes binaries and CNI network
configuration will be placed in a particular location.

Ensure the following directories are created by running the following commands on
each node:

```
mkdir -p /var/run/calico
mkdir -p /var/log/calico
mkdir -p /opt/bin
mkdir -p /etc/rkt/net.d
```

#### Run `calico/node` and configure the node.

Each Calico-rkt enabled node requires the `calico/node` container to be running.

The calico/node container can be run directly through rkt and needs to be run as
as fly stage-1 container.

```shell
sudo rkt run --stage1-path=/usr/share/rkt/stage1-fly.aci \
  --set-env=ETCD_ENDPOINTS=http://<ETCD_IP>:<ETCD_PORT> \
  --set-env=IP=autodetect \
  --insecure-options=image \
  --volume=birdctl,kind=host,source=/var/run/calico,readOnly=false \
  --mount=volume=birdctl,target=/var/run/calico \
  --volume=mods,kind=host,source=/lib/modules,readOnly=false  \
  --mount=volume=mods,target=/lib/modules \
  --volume=logs,kind=host,source=/var/log/calico,readOnly=false \
  --mount=volume=logs,target=/var/log/calico \
  --net=host \
  quay.io/calico/node:{{site.data.versions[page.version].first.title}} &
```

> Replace `<ETCD_IP>:<ETCD_PORT>` with your etcd configuration.  The `ETCD_ENDPOINTS`
> environment may contain a comma separated list of endpoints of your etcd cluster.
> If the environment is omitted, Calico defaults to a single etcd
> endpoint at http://127.0.0.1:2379.

You can check that it's running using `sudo rkt list`.

```shell
$ sudo rkt list
UUID      APP	IMAGE NAME                  STATE   CREATED         STARTED         NETWORKS
b52bba11  node  quay.io/calico/node:{{site.data.versions[page.version].first.title}}  running 10 seconds ago  10 seconds ago
```

## Installing calicoctl
   Download the calicoctl binary:

   ```
   sudo wget -O /usr/local/bin/calicoctl {{site.data.versions[page.version].first.components.calicoctl.download_url}}
   sudo chmod +x calicoctl
   ```

The [`calicoctl` documentation]({{site.baseurl}}/{{page.version}}/reference/calicoctl/) has commandline options and configuration.

### Running calicoctl as a container

Alternatively to downloading the `calicoctl` binary it can be run as a container.

```
sudo rkt run quay.io/calico/ctl --exec /calicoctl -- version
```

To also specify the ETCD_ENDPOINTS use:

```
sudo rkt run --set-env=ETCD_ENDPOINTS="http://etcd1:2379" quay.io/calico/ctl --exec /calicoctl -- version
```

## Installing Calico as a CNI plugin

To install Calico as a CNI plugin used by rkt, we need to first install the
actual plugin binaries, and then once installed create any CNI networks that you
require with the appropriate Calico CNI plugin references.

#### Install the Calico plugin binaries

Download the binaries and make sure they're executable.  We download to the
`/etc/rkt/net.d` directory since it is one of the default locations that rkt uses
for config discovery.  You may change the location and override the rkt configuration
if desired.

```bash
wget -N -P /etc/rkt/net.d {{site.data.versions[page.version].first.components["calico/cni"].download_calico_url}}
wget -N -P /etc/rkt/net.d {{site.data.versions[page.version].first.components["calico/cni"].download_calico_ipam_url}}
chmod +x /etc/rkt/net.d/calico /etc/rkt/net.d/calico-ipam
```

The Calico CNI plugins require a standard CNI config file.

#### Create a Calico network

To define a rkt network for Calico, create a configuration file in `/etc/rkt/net.d/`.

- Each network should be given a unique "name".
- Specify the CNI specification version with "cniVersion", for example "cniVersion": "0.1.0".
- To use Calico networking, specify "type": "calico"
- To use Calico IPAM, specify "type": "calico-ipam" in the "ipam" section.

Calico will create an identically named profile for each Calico-rkt network which, by
default, contains policy to allow full communication between containers within the same
network (i.e. using the same profile) but prohibit ingress traffic from containers
on other networks.

The same network configuration needs to be added to each node for the network
to be discoverable on that node.  Mutliple networks may be created using unique names.

For example, run the following to create a network called "mynet"

```shell
cat >/etc/rkt/net.d/10-calico-mynet.conf <<EOF
{
    "name": "mynet",
    "cniVersion": "0.1.0",
    "etcd_endpoints": "http://<ETCD_IP>:<ETCD_PORT>",
    "type": "calico",
    "ipam": {
        "type": "calico-ipam"
    }
}
EOF
```

> Replace `<ETCD_IP>:<ETCD_PORT>` with your etcd configuration.  The `etcd_endpoints`
> paramater may contain a comma separated list of endpoints of your etcd cluster.
> If the parameter is omitted from the config file, Calico defaults to a single etcd
> endpoint at http://127.0.0.1:2379.

## Next steps

Now that you have your cluster setup, see the
[Basic Network Isolation guide]({{site.baseurl}}/{{page.version}}/getting-started/rkt/tutorials/basic)
for an example of managing Calico policy with your rkt containers.
