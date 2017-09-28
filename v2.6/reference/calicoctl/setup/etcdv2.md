---
title: Configuring calicoctl - etcdv2 datastore
redirect_from: latest/reference/calicoctl/setup/etcdv2
---

This document covers the configuration options for calicoctl when using an etcdv2 datastore.

There are two ways to configure calicoctl with your etcdv2 cluster details:
configuration file or environment variables.


## Configuration File

By default `calicoctl` looks for a configuration file at `/etc/calico/calicoctl.cfg`.

The file location may be overridden using the `--config` option on commands that required
datastore access.

The config file is a yaml or json document in the following format:

```
apiVersion: v1
kind: calicoApiConfig
metadata:
spec:
  datastoreType: "etcdv2"
  etcdEndpoints: "http://etcd1:2379,http://etcd2:2379"
  ...
```

See table below for details on the etcdv2 specific fields that may be included in
the spec section.

If the file exists, then it must be valid and readable by calicoctl.  If the file
does not exist, calicoctl will read access details from the environment variables.

## Environment variables

If you are not using a config file to specify your access information, calicoctl
will check a particular set of environment variables.

See the table below for details on the etcdv2 specific environment variables.

> **Note**: If neither file nor environment variables are set, calicoctl defaults to
> using etcdv2 with a single endpoint of http://127.0.0.1:2379.
{: .alert .alert-info}


## Complete list of etcdv2 connection configuration

| Setting (Environment variable)     | Description                                                                            | Schema
| ---------------------------------- | -------------------------------------------------------------------------------------- | ------
| datastoreType (DATASTORE_TYPE)     | Indicates the datastore to use [Default: `etcdv2`] (optional)                          | kubernetes, etcdv2
| etcdEndpoints (ETCD_ENDPOINTS)     | A comma separated list of etcd endpoints [Default: `http://127.0.0.1:2379]` (optional) | string
| etcdUsername (ETCD_USERNAME)       | Username for RBAC, e.g. `user` (optional)                                              | string
| etcdPassword (ETCD_PASSWORD)       | Password for the given username, e.g. `password` (optional)                            | string
| etcdKeyFile (ETCD_KEY_FILE)        | Path to the etcd key file, e.g. `/etc/calico/key.pem` (optional)                       | string
| etcdCertFile (ETCD_CERT_FILE)      | Path to the etcd client cert, e.g. `/etc/calico/cert.pem` (optional)                   | string
| etcdCACertFile (ETCD_CA_CERT_FILE) | Path to the etcd CA file, e.g. `/etc/calico/ca.pem` (optional)                         | string

> **Note**:
> - If you are running with TLS enabled, ensure your endpoint addresses use HTTPS.
> - When specifying through environment variables, the `DATASTORE_TYPE` environment
>   is not required for etcdv2.
> - All environment variables may also be prefixed with `CALICO_`, for example
>   `CALICO_DATASTORE_TYPE` and `CALICO_ETCD_ENDPOINTS` etc. may also be used.
>   This is useful if the non-prefixed names clash with existing environment
>   variables defined on your system
> - Previous versions of `calicoctl` supported `ETCD_SCHEME` and `ETC_AUTHORITY` environment
>   variables as a mechanism for specifying the etcd endpoints. These variables are
>   deprecated in favor of the `ETCD_ENDPOINTS` list.
{: .alert .alert-info}


## Examples

#### Example configuration file

```yaml
apiVersion: v1
kind: calicoApiConfig
metadata:
spec:
  etcdEndpoints: http://etcd1:2379,http://etcd2:2379,http://etcd3:2379
  etcdKeyFile: /etc/calico/key.pem
  etcdCertFile: /etc/calico/cert.pem
  etcdCACertFile: /etc/calico/ca.pem
```

#### Example using environment variables

```
ETCD_ENDPOINTS=http://myhost1:2379 calicoctl get bgppeers
```

#### Example using IPv6

Create a single node etcd cluster listening on IPv6 localhost `[::1]`.

```
etcd --listen-client-urls=http://[::1]:2379 --advertise-client-urls=http://[::1]:2379
```

Use the etcd IPv6 cluster:

```
ETCD_ENDPOINTS=http://[::1]:2379 calicoctl get bgppeers
```

#### Example using mixed IPv4/IPv6

Create a single node etcd cluster listening on IPv4 and IPv6 localhost `[::1]`.

```
etcd --listen-client-urls=http://[::1]:2379,http://127.0.0.1:2379 --advertise-client-urls=http://[::1]:2379
```

Use the IPv6 endpoint:

```
ETCD_ENDPOINTS=http://[::1]:2379 calicoctl get bgppeers
```

Use the IPv4 endpoint:

```
ETCD_ENDPOINTS=http://127.0.0.1:2379 calicoctl get bgppeers
```

## calico/node

It is important to note that not only will calicoctl will use the specified keys directly
on the host to access etcd, **it will also pass on these environment variables
and volume mount the keys into the started calico-node container.**

Therefore, configuring calico-node for etcd is easily accomplished by running
`calicoctl node run` with the parameters set correctly.
