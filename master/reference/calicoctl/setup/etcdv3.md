---
title: Configuring calicoctl - etcdv3 datastore
no_canonical: true
---

This document covers the configuration options for calicoctl when using an etcdv3 datastore.

There are two ways to configure calicoctl with your etcdv3 cluster details:
- [Configuration file](#configuration-file)
- [Environment variables](#environment-variables)


## Configuration file

By default `calicoctl` looks for a configuration file at `/etc/calico/calicoctl.cfg`.

The file location may be overridden using the `--config` option on commands that required
datastore access.

You can use either YAML or JSON for the configuration file. A YAML example follows.

```
apiVersion: projectcalico.org/v3
kind: CalicoAPIConfig
metadata:
spec:
  datastoreType: "etcdv3"
  etcdEndpoints: "http://etcd1:2379,http://etcd2:2379"
  ...
```

See [Complete list of etcdv3 configuration options](#complete-list-of-etcdv3-configuration-options) 
for details on the etcdv3 configuration options that may be included in
the `spec` section of the configuration file.

If the file exists, then it must be valid and readable by calicoctl.  If the file
does not exist, calicoctl will read etcdv3 configuration options from the environment variables.

## Environment variables

If you are not using a configuration file to specify your etcdv3 access information, calicoctl
will check a particular set of environment variables.

See [Complete list of etcdv3 configuration options](#complete-list-of-etcdv3-configuration-options) 
for the list of supported environment variables.


## Complete list of etcdv3 configuration options

| Configuration file option  | Environment variable | Description                                                                           | Schema
| ---------------------------| -------------------- | ------------------------------------------------------------------------------------- | ------
| `datastoreType`            | `DATASTORE_TYPE`     | Indicates the datastore to use. If unspecified, defaults to `etcdv3`. (optional)      | `kubernetes`, `etcdv3`
| `etcdEndpoints`            | `ETCD_ENDPOINTS`     | A comma separated list of etcd endpoints. Example: `http://127.0.0.1:2379` (required) | string
| `etcdUsername`             | `ETCD_USERNAME`      | User name for RBAC. Example: `user` (optional)                                        | string
| `etcdPassword`             | `ETCD_PASSWORD`      | Password for the given user name. Example: `password` (optional)                      | string
| `etcdKeyFile`              | `ETCD_KEY_FILE`      | Path to the etcd key file. Example: `/etc/calico/key.pem` (optional)                  | string
| `etcdCertFile`             | `ETCD_CERT_FILE`     | Path to the etcd client certificate, Example: `/etc/calico/cert.pem` (optional)       | string
| `etcdCACertFile`           | `ETCD_CA_CERT_FILE`  | Path to the etcd Certificate Authority file. Example: `/etc/calico/ca.pem` (optional) | string

> **Note**:
> - If you are running with TLS enabled, ensure your endpoint addresses use HTTPS.
> - When specifying through environment variables, the `DATASTORE_TYPE` environment
>   is not required for etcdv3.
> - All environment variables may also be prefixed with `CALICO_`, for example
>   `CALICO_DATASTORE_TYPE` and `CALICO_ETCD_ENDPOINTS` etc. may also be used.
>   This is useful if the non-prefixed names clash with existing environment
>   variables defined on your system
> - Previous versions of `calicoctl` supported `ETCD_SCHEME` and `ETC_AUTHORITY` environment
>   variables as a mechanism for specifying the etcd endpoints. These variables are
>   no longer supported. Use `ETCD_ENDPOINTS` instead.
{: .alert .alert-info}


## Examples

#### Example configuration file

```yaml
apiVersion: projectcalico.org/v3
kind: CalicoApiConfig
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
