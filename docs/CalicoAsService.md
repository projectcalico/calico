<!--- master only -->
> ![warning](./images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Running Calico Node Containers as Services

This guide explains how to run Calico as a system process or service,
with a focus on running in a Dockerized deployment. We include
examples for Systemd, but the commands can be applied to other init
daemons such as upstart as well.

## Running the Calico Node Container as a Service
Running the `calicoctl node` command will start the Calico process as a
container in Docker.  By default, the container will start in "detached" mode,
meaning the container is running in the background.  To run the Calico node
in the foreground, you can run:
```
calicoctl node --detach=false
```

This command will allow you to run the Calico node container as a service that
attaches to the container process that is running Calico.

**NOTE**: When running the `calicoctl node` with `--detach=false`, you are not able to
include the `--libnetwork` flag that starts Calico's Docker networking plugin.
This won't work because Calico's libnetwork plugin runs as a separate
container.  Instead, you can start Calico's libnetwork plugin as its own
service as well (see section below on **Running Calico as a Docker Network
Plugin Service**).

Included here is an EnvironmentFile that defines the Environment variables for
Calico and a sample systemd service file that uses the environment file and
starts the Calico node image as a service.

`calico.env` - the EnvironmentFile:
```
ETCD_AUTHORITY=localhost:2379
ETCD_SCHEME=http
ETCD_CA_FILE=""
ETCD_CERT_FILE=""
ETCD_KEY_FILE=""
```

Be sure to update this environment file as necessary, such as modifying the
ETCD_AUTHORITY value to point at the correct instance of Etcd.

> Note: The ETCD_SCHEME, ETCD_CA_FILE, ETCD_CERT_FILE, and ETCD_KEY_FILE
> environment variables are required when using Etcd with SSL/TLS.  The values
> here are standard values for a non-SSL version of Etcd, but you can use this
> template to define your SSL values if desired.  For more details about running
> Calico with Etcd using SSL/TLS, check out the
> [Etcd Secure Cluster guide](EtcdSecureCluster.md).

### Systemd Service Example

`calico-node.service` - the Systemd service:

```
[Unit]
Description=calico-node
After=docker.service
Requires=docker.service

[Service]
EnvironmentFile=/etc/calico/calico.env
ExecStartPre=-/usr/bin/docker rm -f calico-node
ExecStart=/usr/bin/calicoctl node --detach=false
ExecStop=-/usr/bin/docker stop calico-node

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

## Running Calico as a Docker Network Plugin Service
If you are running Calico as a Docker network plugin, it is also necessary to
have a separate job for handling the Calico libnetwork driver.

You can start the `calico/node-libnetwork` image directly with the `docker run`
command:

```
docker run --privileged --net=host \
    -v /run/docker/plugins:/run/docker/plugins \
    --name=calico-libnetwork -e ETCD_AUTHORITY=localhost:2379
    calico/node-libnetwork
```

In this example,

 - Privileged is required since the container creates network devices.
 - Host network is used since the network changes need to occur in the host namespace
 - The /run/docker/plugins volume is used to allow the plugin to communicate with Docker.

### Systemd Service Example

This service uses the same EvnironmentFile as `calico-node.service` above. Again,
make sure you update the environment variables in this file to reflect the
correct values for your deployment.  It is safe to specify the `-e` flag as seen
below even if the environment variable is not set.

`calico-libnetwork.service`

```
[Unit]
Description=calico-libnetwork
After=docker.service
Requires=docker.service

[Service]
EnvironmentFile=/etc/calico/calico.env
ExecStartPre=-/usr/bin/docker rm -f calico-libnetwork
ExecStart=/usr/bin/docker run --privileged --net=host \
 -v /run/docker/plugins:/run/docker/plugins \
 --name=calico-libnetwork \
 -e ETCD_AUTHORITY=${ETCD_AUTHORITY} \
 -e ETCD_SCHEME=${ETCD_SCHEME} \
 -e ETCD_CA_CERT_FILE=${ETCD_CA_CERT_FILE} \
 -e ETCD_CERT_FILE=${ETCD_CERT_FILE} \
 -e ETCD_KEY_FILE=${ETCD_KEY_FILE} \
 calico/node-libnetwork:latest
ExecStop=-/usr/bin/docker stop calico-libnetwork

[Install]
WantedBy=multi-user.target
```

This Systemd service does the following on start:
  - Confirm docker is installed under the `[Unit]` section
  - Get environment variables from the environment file above
  - Remove existing `calico-libnetwork` container (if it exists)
  - Start `calico/node-libnetwork` image with docker, passing in environment variables

The script will also stop the calico-libnetwork container when the service is stopped.

**Note**: As with the `calico/node` service example, the name of the Docker service under
the `[Unit]` section may be different (such `docker-engine.service`) depending
on how you've installed Docker.
Be sure to check this before starting the service.

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/CalicoAsService.md?pixel)](https://github.com/igrigorik/ga-beacon)
