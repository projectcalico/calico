---
title: Running calico/node with an init system
canonical_url: https://docs.projectcalico.org/v3.3/usage/configuration/as-service
---

This guide explains how to run `calico/node` with an init system like
systemd, inside either of the following container types:
- [Docker](#running-caliconode-in-a-docker-container)
- [rkt](#running-caliconode-in-a-rkt-container)

## Running calico/node in a Docker container

This section describes how to run `calico/node` as a Docker container.

> **Note**: We include examples for systemd, but the commands can be
> applied to other init daemons such as upstart.
{: .alert .alert-info}

Included here is an `EnvironmentFile` that defines the environment
variables for Calico and a sample systemd service file that uses the
environment file and starts the `calico/node` image as a service.

`calico.env` - the `EnvironmentFile`:

```shell
ETCD_ENDPOINTS=http://localhost:2379
ETCD_CA_FILE=""
ETCD_CERT_FILE=""
ETCD_KEY_FILE=""
CALICO_NODENAME=""
CALICO_NO_DEFAULT_POOLS=""
CALICO_IP=""
CALICO_IP6=""
CALICO_AS=""
CALICO_NETWORKING_BACKEND=bird
```

Be sure to update this environment file as necessary, such as modifying
ETCD_ENDPOINTS to point at the correct etcd cluster endpoints.

> **Note**: The `ETCD_CA_FILE`, `ETCD_CERT_FILE`, and `ETCD_KEY_FILE`
> environment variables are required when using etcd with SSL/TLS. The values
> here are standard values for a non-SSL version of etcd, but you can use this
> template to define your SSL values if desired.
>
> If `CALICO_NODENAME` is blank, the compute server hostname will be used
> to identify the Calico node.
>
> If `CALICO_IP` or `CALICO_IP6` are left blank, Calico will use the currently
> configured values for the next hop IP addresses for this node—these can
> be configured through the node resource.  If no next hop addresses have
> been configured, Calico will automatically determine an IPv4 next hop address
> by querying the host interfaces (and it will configure this value in the
> node resource). You may set `CALICO_IP` to `autodetect` to force
> auto-detection of IP address every time the node starts. If you set IP
> addresses through these environments it will reconfigure any values currently
> set through the node resource.
>
> If `CALICO_AS` is left blank, Calico will use the currently configured value
> for the AS Number for the node BGP client—this can be configured through
> the node resource. If no value is set,  Calico will inherit the AS Number
> from the global default value. If you set a value through this environment
> it will reconfigure any value currently set through the node resource.
>
> The `CALICO_NETWORKING_BACKEND` defaults to use BIRD as the routing daemon.
> This may also be set to `gobgp` (to use GoBGP as the routing daemon, but note
> that this does not support IP-in-IP), or `none` (if routing is handled by an
> alternative mechanism).
{: .alert .alert-info}


### systemd service example

`calico-node.service` - the systemd service:

```shell
[Unit]
Description=calico-node
After=docker.service
Requires=docker.service

[Service]
EnvironmentFile=/etc/calico/calico.env
ExecStartPre=-/usr/bin/docker rm -f calico-node
ExecStart=/usr/bin/docker run --net=host --privileged \
 --name=calico-node \
 -e NODENAME=${CALICO_NODENAME} \
 -e IP=${CALICO_IP} \
 -e IP6=${CALICO_IP6} \
 -e CALICO_NETWORKING_BACKEND=${CALICO_NETWORKING_BACKEND} \
 -e AS=${CALICO_AS} \
 -e NO_DEFAULT_POOLS=${CALICO_NO_DEFAULT_POOLS} \
 -e ETCD_ENDPOINTS=${ETCD_ENDPOINTS} \
 -e ETCD_CA_CERT_FILE=${ETCD_CA_CERT_FILE} \
 -e ETCD_CERT_FILE=${ETCD_CERT_FILE} \
 -e ETCD_KEY_FILE=${ETCD_KEY_FILE} \
 -v /var/log/calico:/var/log/calico \
 -v /run/docker/plugins:/run/docker/plugins \
 -v /lib/modules:/lib/modules \
 -v /var/run/calico:/var/run/calico \
 {{site.imageNames["node"]}}:{{site.data.versions[page.version].first.title}}

ExecStop=-/usr/bin/docker stop calico-node

Restart=on-failure
StartLimitBurst=3
StartLimitInterval=60s

[Install]
WantedBy=multi-user.target
```

The systemd service above does the following on start:
  - Confirm Docker is installed under the `[Unit]` section
  - Get environment variables from the environment file above
  - Remove existing `calico-node` container (if it exists)
  - Start `calico/node`

The script will also stop the calico-node container when the service is stopped.

> **Note**: Depending on how you've installed Docker, the name of the Docker service
> under the `[Unit]` section may be different (such as `docker-engine.service`).
> Be sure to check this before starting the service.
{: .alert .alert-info}


## Running calico/node in a rkt container

Each Calico-rkt enabled node requires the `calico/node` container to be running.

The `calico/node` container can be run directly through rkt and needs to be run as
as a fly stage-1 container.

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
  {{site.imageNames["node"]}}:{{site.data.versions[page.version].first.title}} &
```

> **Note**: Replace `<ETCD_IP>:<ETCD_PORT>` with your etcd configuration. The `ETCD_ENDPOINTS`
> environment may contain a comma separated list of endpoints of your etcd cluster.
{: .alert .alert-info}

You can check that it's running using `sudo rkt list`.

```shell
$ sudo rkt list
UUID      APP	IMAGE NAME                  STATE   CREATED         STARTED         NETWORKS
b52bba11  node  {{site.imageNames["node"]}}:{{site.data.versions[page.version].first.title}}  running 10 seconds ago  10 seconds ago
```
