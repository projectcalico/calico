<!--- master only -->
> ![warning](./images/warning.png) This document applies to the HEAD of the calico-docker source tree.
>
> View the calico-docker documentation for the latest release [here](https://github.com/projectcalico/calico-docker/blob/v0.12.0/README.md).
<!--- else
> You are viewing the calico-docker documentation for release **release**.
<!--- end of master only -->

# Using Calico with a Secure Etcd Cluster

Calico supports basic etcd clusters as well as clusters running with SSL/TLS.

## Etcd with Client and Server Verification

Calico utilizes the following environment variables when creating its secure 
etcd client:

- **`ETCD_AUTHORITY`**: The `<ip_address>:<port_number>` pair representing the 
 access point to the cluster. **Default**: 127.0.0.1:2379
- **`ETCD_SCHEME`**: The http or https protocol used by the etcd datastore. 
 **Default**: http
- **`ETCD_CA_CERT_FILE`**: The full path to the CA certificate file for the 
 Certificate Authority that signed the etcd server key/certificate pair.
- **`ETCD_CERT_FILE`**: The full path to the client certificate file for 
 accessing the etcd cluster.
- **`ETCD_KEY_FILE`**: The full path to the client key file for accessing the 
 etcd cluster.


### Setting Environment Variables
To configure your setup, you must set these values on your machine, such as 
the following:
```
ETCD_AUTHORITY=127.0.0.1:2379; export ETCD_AUTHORITY
ETCD_SCHEME=https; export ETCD_SCHEME
ETCD_CA_CERT_FILE=/path/to/ca.crt; export ETCD_CA_CERT_FILE
ETCD_CERT_FILE=/path/to/cert.crt; export ETCD_CERT_FILE
ETCD_KEY_FILE=/path/to/key.pem; export ETCD_KEY_FILE
```
> NOTE: The file extensions are not important, the files just need to exist and 
> be readable.

### Commands that Require Root
Some commands are required to be run as root.  The user's environment variables 
specified above will not be recognized by the root user, so the variables must 
be passed into the Calico command.

For example, to run `calicoctl node`, you would call something like this:
```
sudo ETCD_SCHEME=https ETCD_KEY_FILE=/path/to/client.key \
     ETCD_CA_CERT_FILE=/path/to/ca.crt ETCD_CERT_FILE=/path/to/client.crt \
     ETCD_AUTHORITY=127.0.0.1:2379 dist/calicoctl node
```

Here's a list of commands that must be run as root:
- `calicoctl node`
- `calicoctl node stop`
- `calicoctl node remove`
- `calicoctl container add`
- `calicoctl container remove`
- `calicoctl container ip add`
- `calicoctl container ip remove`

See the [calicoctl reference guide](./calicoctl.md) for details on specific 
calicoctl commands.

### Docker Libnetwork

If are using Docker with the libnetwork networking driver, you will have to
supply additional parameters to the Docker daemon to recognize your secure
etcd cluster:

     --cluster-store-opt kv.cacertfile=/path/to/ca.crt
     --cluster-store-opt kv.certfile=/path/to/cert.crt
     --cluster-store-opt kv.keyfile=/path/to/key.pem
