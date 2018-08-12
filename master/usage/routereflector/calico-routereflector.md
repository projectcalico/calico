---
title: Calico BIRD Route Reflector container
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v3.1/usage/routereflector/calico-routereflector'
---

For many {{site.prodname}} deployments, the use of a Route Reflector is not required.
However, for large scale deployments a full mesh of BGP peerings between each
of your {{site.prodname}} nodes may become untenable.  In this case, route reflectors
allow you to remove the full mesh and scale up the size of the cluster.

This guide discusses the calico/routereflector image: a container image that
packages up the `BIRD` BGP daemon along with the `confd` templating engine to
provide a simple route reflector image which may be used for scaled-out {{site.prodname}}
deployments.

The image is currently experimental and has some key limitations discussed below.
However, it may provide a useful framework for future development.

These instructions are focused on container-based deployments that use the
`{{site.nodecontainer}}` container image.

For an OpenStack deployment, read [Configuring BIRD as a BGP Route Reflector](bird-rr-config).

> **Note**: The API and behavior of `calico/routereflector` is likely to change in
> future releases.
{: .alert .alert-info}


#### Known limitations

-  The `calico/routereflector` instance will automatically peer with the {{site.prodname}}
   nodes, but it currently has no mechanism to configure peerings with non-{{site.prodname}}
   BGP speakers (e.g. edge routers)
-  There is no `calicoctl` integration or similar.
-  If you are using Kubernetes API as the {{site.prodname}} datastore, the Route Reflector container
   currently only supports running as a single-instance.
-  For etcdv3, the Route Reflector container may be used to form a cluster of route reflectors that
   automatically create a full mesh between each Route Reflector.
   -  Note that there is no `calicoctl` integration and to form a cluster it is necessary to
      configure data directly into the `etcd` datastore for each Route Reflector instance.
   -  It is not possible to form multiple separate meshed groups
      of Route Reflectors using this image.

## Starting and configuring your route reflectors

Follow the appropriate section to start and configure your route reflectors depending on
the datastore you are using for {{site.prodname}}:

-  [Using etcdv3 as the {{site.prodname}} datastore](#using-etcdv3-as-the-calico-datastore)
-  [Using the Kubernetes API as the {{site.prodname}} datastore](#using-the-kubernetes-api-as-the-calico-datastore)

### Using etcdv3 as the {{site.prodname}} datastore

#### Starting a Route Reflector instance

On your Route Reflector host, ensure you have [Docker v1.6](http://www.docker.com) or greater
installed.

Run the following command to start the Route Reflector container image.

```
docker run --privileged --net=host -d                              \
           -e IP=<IPv4_RR>                                         \
           [-e IP6=<IPv6_RR>]                                      \
           -e ETCD_ENDPOINTS=<http://ETCD_IP:PORT>                 \
           calico/routereflector:{{site.data.versions[page.version].first.components["calico/routereflector"].version}}
```

Where:

-  `[]` indicates an optional parameter
-  `<IPv4_RR>` is the IPv4 address of the RR host (the BIRD instance binds to
   the hosts IPv4 address)
-  `<IPv6_RR>` is the *optional* IPv6 address of the RR host (the BIRD6 instance
   binds to the hosts IPv6 address)
-  `<ETCD_IP:PORT>` is the colon separated IPv4 address and port of an etcd
   node in the etcd cluster.  A comma-separated list of endpoints may be
   specified.

> **Note**: If you require TLS/SSL-enabled etcd, see the
> [section below](#route-reflector-with-tlsssl-etcd)
> for details on how to start the route reflector.
{: .alert .alert-info}

#### Route Reflector with TLS/SSL Etcd

If you are running secure etcd, you will need to pass in additional options
and set environment variables for the certificate and key files associated
with your etcd instance.

When starting the Route Reflector container image, you need to mount the
certificate files and environment variable filepaths for each file:

```
docker run --privileged --net=host -d                              \
           -e IP=<IPv4_RR>                                         \
           [-e IP6=<IPv6_RR>]                                      \
           -e ETCD_ENDPOINTS=<https://ETCD_IP:PORT>                \
           -v <FULL_PATH_TO_CERT_DIR>:<MOUNT_DIR>                  \
           -e ETCD_CA_CERT_FILE=<MOUNT_DIR>/<CA_FILE>              \
           -e ETCD_CERT_FILE=<MOUNT_DIR>/<CERT_FILE>               \
           -e ETCD_KEY_FILE=<MOUNT_DIR>/<KEY_FILE>                 \
           calico/routereflector:{{site.data.versions[page.version].first.components["calico/routereflector"].version}}
```

Where `<FULL_PATH_TO_CERT_DIR>` is a directory on the host that contains
the certificate files (you can mount multiple directories with additional
`-v <DIR>` parameters if they are in separate directories, but be sure
to choose different `<MOUNT_DIR>` locations if this is the case).

### Using the Kubernetes API as the {{site.prodname}} datastore

If you are using Kubernetes as the datastore for {{site.prodname}}, the {{site.prodname}} Route
Reflector container only supports running as a single route reflector.  It is not
possible with this image to set up a cluster of route reflectors.

#### Starting up the Route Reflector

On your Route Reflector host, ensure you have [Docker v1.6](https://docs.docker.com/engine/installation/) or greater
installed.

You will need a kubeconfig file that you need to mount into the route reflector
container.

Run the following command to start the Route Reflector container image.

```
docker run --privileged --net=host -d                              \
           -e DATASTORE_TYPE=kubernetes                            \
           -e KUBECONFIG=/kubeconfig                               \
           -e IP=<IPv4_RR>                                         \
           -v <KUBECONFIG FILE PATH>:/kubeconfig                   \
           calico/routereflector:{{site.data.versions[page.version].first.components["calico/routereflector"].version}}
```

Where:

-  `<IPv4_RR>` is the IPv4 address of the RR host (the BIRD instance binds to
   the hosts IPv4 address)
-  `<KUBECONFIG FILE PATH>` is the path to the kubeconfig file.

When using Kubernetes API as the datastore, this route reflector image only works
as a single standalone reflector.


## Configuring {{site.prodname}} to use the route reflectors

Run through this section  to set up the global {{site.prodname}} configuration
before configuring any nodes.  This only needs to be done once.

-  Disable the full node-to-node BGP mesh
-  Configure the default node AS number for your network (this is used by
   the Route Reflector image when setting up the Route Reflector full mesh).

If you have a small cluster of Route Reflectors and you intend to have every
{{site.prodname}} Docker node peer with every Route Reflector, set this up one time as
global configuration.


### Turn off the full node-to-node mesh

From any {{site.prodname}} Docker node, run the following:

```
# Get the current bgpconfig settings
$ calicoctl get bgpconfig -o yaml > bgp.yaml

# Set nodeToNodeMeshEnabled to false
$ vim bgp.yaml

# Replace the current bgpconfig settings
$ calicoctl replace -f bgp.yaml
```

### Determine the AS number for your network

From any {{site.prodname}} Docker node, run the following:

    calicoctl get nodes --output=wide

This returns table of all configured {{site.prodname}} node instances and includes the AS
number for each node.

### Peering with every Route Reflector (optional)

If you have a small cluster of Route Reflectors (e.g. a single RR or a pair of
RRs for redundancy) and you intend to have every {{site.prodname}} Docker node peer with
each of the Route Reflectors, you can set up the peerings as a one-time set of
global configuration.

Use `calicoctl` to configure each route reflector as a global peer (i.e. it
peers with every node in the deployment):

```
calicoctl bgp peer add <IP_RR> as <AS_NUM>
$ calicoctl create -f - << EOF
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: bgppeer-global
spec:
  peerIP: <IP_RR>
  asNumber: <AS_NUM>
EOF
```

Where:
-  `<IP_RR>` is the IPv4 or IPv6 address of the Route Reflector.
-  `<AS_NUM>` is the AS number to use for the network (set or determined
   above).

## Setting up node-specific peering

If you are deploying a cluster of Route Reflectors, with each {{site.prodname}} node
peering to a subset of Route Reflectors it will be necessary to set up the
peerings on a node-by-node basis.

This would be the typical situation when scaling out to a very large size.  For
example, you may have:

-  a cluster of 100 route reflectors connected in a full mesh
-  a network of 100,000 {{site.prodname}} Docker nodes
-  each {{site.prodname}} Docker node is connected to two or three different Route
   Reflectors.

### Configuring a node-specific Route Reflector peering

To configure a Route Reflector as a peer of a specific node, run the following
*from the node*:

```
$ cat << EOF | calicoctl create -f -
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: bgppeer-2
spec:
  peerIP: <IP_RR>
  node: <NODENAME>
  asNumber: <AS_NUM>
EOF
```

Where:
-  `<IP_RR>` is the IPv4 or IPv6 address of the Route Reflector.
-  `<AS_NUM>` is the AS number to use for the network (set or determined
   above).
-  `<NODENAME>` is the name of the node.

Run this separately for each Route Reflector that you want to peer with the
node.
