---
title: Running Calico Node Container as a Service
canonical_url: 'https://docs.projectcalico.org/v3.5/usage/configuration/as-service'
---

This guide explains how to run Calico as a system process or service,
with a focus on running in a Dockerized deployment. We include
examples for Systemd, but the commands can be applied to other init
daemons such as upstart as well.

## Running the Calico Node Container as a Service
This section describes how to run the Calico node as a Docker container
in Systemd.  Included here is an EnvironmentFile that defines the Environment 
variables for Calico and a sample systemd service file that uses the 
environment file and starts the Calico node image as a service.

`calico.env` - the EnvironmentFile:

```shell
ETCD_AUTHORITY=localhost:2379
ETCD_SCHEME=http
ETCD_CA_FILE=""
ETCD_CERT_FILE=""
ETCD_KEY_FILE=""
CALICO_HOSTNAME=""
CALICO_NO_DEFAULT_POOLS=""
CALICO_IP=""
CALICO_IP6=""
CALICO_AS=""
CALICO_LIBNETWORK_ENABLED=true
CALICO_NETWORKING_BACKEND=bird
```

Be sure to update this environment file as necessary, such as modifying the
ETCD_AUTHORITY value to point at the correct instance of Etcd.

> Note: The ETCD_SCHEME, ETCD_CA_FILE, ETCD_CERT_FILE, and ETCD_KEY_FILE
> environment variables are required when using Etcd with SSL/TLS.  The values
> here are standard values for a non-SSL version of Etcd, but you can use this
> template to define your SSL values if desired.  For more details about running
> Calico with Etcd using SSL/TLS, check out the
> [Etcd Secure Cluster guide]({{site.baseurl}}/{{page.version}}/reference/advanced/etcd-secure).
>
> If the CALICO_HOSTNAME is blank, the compute server hostname will be used
> to identify the Calico node.
>
> If CALICO_IP and CALICO_IP6 are left blank, the next hop IP addresses for
> this node will be automatically determined by querying the host interfaces.
> It may be necessary to explicitly set these values.
>
> If the CALICO_AS is left blank, the AS Number for the node BGP client will be
> inherited from the global defaut value.  Set this if you need to explicitly
> set the AS Number for this node.
>
> If you do not require Calico for Docker networking, you may set the
> CALICO_LIBNETWORK_ENABLED to false.
>
> The CALICO_NETWORKING_BACKEND defaults to use Bird as the routing daemon.
> This may also be set to gobgp (to use gobgp as the routing daemon, but note
> that this does not support IP in IP), or none (if routing is handled by an
> alternative mechanism).

### Systemd Service Example

`calico-node.service` - the Systemd service:

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
 -e HOSTNAME=${HOSTNAME} \
 -e IP=${CALICO_IP} \
 -e IP6=${CALICO_IP6} \
 -e CALICO_NETWORKING_BACKEND=${CALICO_NETWORKING_BACKEND} \
 -e AS=${CALICO_AS} \
 -e NO_DEFAULT_POOLS=${CALICO_NO_DEFAULT_POOLS} \
 -e CALICO_LIBNETWORK_ENABLED=${CALICO_LIBNETWORK_ENABLED} \
 -e ETCD_AUTHORITY=${ETCD_AUTHORITY} \
 -e ETCD_SCHEME=${ETCD_SCHEME} \
 -e ETCD_CA_CERT_FILE=${ETCD_CA_CERT_FILE} \
 -e ETCD_CERT_FILE=${ETCD_CERT_FILE} \
 -e ETCD_KEY_FILE=${ETCD_KEY_FILE} \
 -v /var/log/calico:/var/log/calico \
 -v /run/docker/plugins:/run/docker/plugins \
 -v /lib/modules:/lib/modules \
 -v /var/run/calico:/var/run/calico \
 calico/node:v0.23.1

ExecStop=-/usr/bin/docker stop calico-node

Restart=on-failure
StartLimitBurst=3
StartLimitInterval=60s

[Install]
WantedBy=multi-user.target
```

The Systemd service above does the following on start:
  - Confirm docker is installed under the `[Unit]` section
  - Get environment variables from the environment file above
  - Remove existing `calico-node` container (if it exists)
  - Start `calico/node`

The script will also stop the calico-node container when the service is stopped.

**Note**: Depending on how you've installed Docker, the name of the Docker service
under the `[Unit]` section may be different (such as `docker-engine.service`).
Be sure to check this before starting the service.

