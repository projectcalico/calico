---
title: Using Calico with a secure etcd cluster
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v1.6/reference/advanced/etcd-secure'
---


Calico supports insecure and TLS/certificate-enabled etcd clusters.

## Etcd with client and server verification

To use TLS-enabled etcd, the following environment variables need to be set
before running any `calicoctl` command:

* **`ETCD_AUTHORITY`**: The `<hostname>:<port_number>` pair representing the 
 access point to the cluster. **Default**: 127.0.0.1:2379
  * NOTE: When running Etcd with TLS enabled, the address of the ETCD_AUTHORITY 
    must be a hostname value, NOT an IP address, such as `etcd-host:2379`.
* **`ETCD_SCHEME`**: The http or https protocol used by the etcd datastore. 
 **Default**: http
* **`ETCD_CA_CERT_FILE`**: The full path to the CA certificate file for the 
 Certificate Authority that signed the etcd server key/certificate pair.
* **`ETCD_CERT_FILE`**: The full path to the client certificate file for 
 accessing the etcd cluster.
* **`ETCD_KEY_FILE`**: The full path to the client key file for accessing the 
 etcd cluster.

For example:

```shell
export ETCD_AUTHORITY=hostname:2379
export ETCD_SCHEME=https
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

For example, to run `calicoctl node`, you would call something like this:

```shell
sudo ETCD_SCHEME=https ETCD_KEY_FILE=/path/to/client.key \
     ETCD_CA_CERT_FILE=/path/to/ca.crt ETCD_CERT_FILE=/path/to/client.crt \
     ETCD_AUTHORITY=hostname:2379 calicoctl node
```

Alternatively, if you have previously defined/exported your environment
variables, you can run `sudo` with the `-E` flag to pass in your environment:

```shell
sudo -E calicoctl node
```

Here's a list of commands that must be run as root:

- `calicoctl node`
- `calicoctl node stop`
- `calicoctl node remove`
- `calicoctl container add`
- `calicoctl container remove`
- `calicoctl container ip add`
- `calicoctl container ip remove`

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

