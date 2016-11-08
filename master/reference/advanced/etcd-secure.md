---
title: Using Calico with a secure etcd cluster
---


Calico supports insecure and TLS/certificate-enabled etcd clusters.

## Etcd with client and server verification

To use TLS-enabled etcd, the following environment variables need to be set
before running any `calicoctl` command:

Variable              | Description                       | Default
----------------------|-----------------------------------|------------------------------
ETCD_ENDPOINTS        | A comma-separated list of etcd cluster endpoints | http://127.0.0.1:2379
ETCD_CA_CERT_FILE     | The full path to the CA certificate file for the Certificate Authority that signed the etcd server key/certificate pair. | None
ETCD_CERT_FILE        | The full path to the client certificate file for accessing the etcd cluster. | None
ETCD_KEY_FILE         | The full path to the client key file for accessing the etcd cluster. | None

For example:

```shell
export ETCD_ENDPOINTS=http://hostname:2379
export ETCD_CA_CERT_FILE=/path/to/ca.pem
export ETCD_CERT_FILE=/path/to/server.pem
export ETCD_KEY_FILE=/path/to/server-key.pem
```

> NOTE: The file extensions are not important, the files just need to exist and 
> be readable.

You can create self-signed certificates using the calico-containers Makefile:

```shell
make ssl-certs
```

This will create the CA certificate, a client certificate/key pair, and a 
server certificate/key pair located at:

```shell
/path/to/calico-containers/certs/ca.pem
/path/to/calico-containers/certs/client.pem
/path/to/calico-containers/certs/client-key.pem
/path/to/calico-containers/certs/server.pem
/path/to/calico-containers/certs/server-key.pem
```

### Commands that require root
Some commands are required to be run as root.  The user's environment variables 
specified above will not be recognized by the root user, so the variables must 
be passed into the Calico command.

For example, to run `calicoctl node run`, you would call something like this:

```shell
sudo ETCD_KEY_FILE=/path/to/client.key \
     ETCD_CA_CERT_FILE=/path/to/ca.crt ETCD_CERT_FILE=/path/to/client.crt \
     ETCD_ENDPOINTS=http://hostname:2379 calicoctl node
```

Alternatively, if you have previously defined/exported your environment
variables, you can run `sudo` with the `-E` flag to pass in your environment:

```shell
sudo -E calicoctl node run
```

See the [calicoctl reference guide]({{site.baseurl}}/{{page.version}}/reference/calicoctl) for details on specific 
calicoctl commands.

### Calico as a Docker network plugin

If you are using Calico as a Docker network plugin, the Docker daemon requires
a KV store for its inbuilt multi-host networking support.  In our tutorials
recommend using etcd for this KV store so that you can have a single store
used by both Docker and Calico.

To run Docker daemon with TLS-enabled etcd, supply the following additional
command line options to the Docker daemon.

     --cluster-store-opt kv.cacertfile=/path/to/ca.crt
     --cluster-store-opt kv.certfile=/path/to/cert.crt
     --cluster-store-opt kv.keyfile=/path/to/key.pem
