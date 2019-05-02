---
title: Installing and configuring calico-upgrade
canonical_url: 'https://docs.projectcalico.org/v3.5/getting-started/kubernetes/upgrade/setup'
---


## Requirements

A host with connectivity to the existing etcdv2 datastore as well as the
target etcdv3 cluster. The host must be AMD64 and running one of the following:

- OS X or macOS
- Linux
- Windows


## Installing calico-upgrade

1. [Download the `calico-upgrade` binary appropriate to your operating system](https://github.com/projectcalico/calico-upgrade/releases/latest).

   > **Tip**: Consider downloading it to a location that's already in your `PATH`. For example, 
   > `/usr/local/bin/`. Alternatively, add its location to your `PATH`. Once it's in your `PATH`, 
   > you can invoke it without having to prepend its location.
   {: .alert .alert-success}

1. Set the file to be executable.

   ```
   chmod +x calico-upgrade
   ```
   
1. Congratulations! You've installed `calico-upgrade`. Continue to [Configuring calico-upgrade](#configuring-calico-upgrade).


## Configuring calico-upgrade

### About configuring calico-upgrade

You must configure `calico-upgrade` so that it can connect to both of the
following:

- [The existing etcdv2 datastore used by Calico v2.6.5](#configuring-calico-upgrade-to-connect-to-the-etcdv2-datastore)

- [The etcdv3 cluster you plan to use for Calico v3.0](#configuring-calico-upgrade-to-connect-to-the-etcdv3-cluster)


### Configuring calico-upgrade to connect to the etcdv2 datastore

You can use either configuration files or environment variables to configure
`calico-upgrade`. It checks these in the following order of precedence.

1. **Configuration file**: The file can be in either YAML or JSON format. It 
   must be valid and readable by `calico-upgrade`. A YAML example follows.

   ```
   apiVersion: v1
   kind: calicoApiConfig
   metadata:
   spec:
     datastoreType: "etcdv2"
     etcdEndpoints: "http://etcd1:2379,http://etcd2:2379"
     ...
   ```

1. **Environment variables**: If `calico-upgrade` cannot locate, read, or access an 
   etcdv2 configuration file, it checks a specific set of environment variables 
   (itemized below).

The full list of possible configuration file options and environment variables follows.

| Configuration file option | Environment variable      | Description                                                                           | Schema
| ------------------------- | ------------------------- | ------------------------------------------------------------------------------------- | --------
| `datastoreType`           | `APIV1_DATASTORE_TYPE`    | Indicates the datastore to use. Default: `etcdv2`. (optional)                         | `etcdv2`
| `etcdEndpoints`           | `APIV1_ETCD_ENDPOINTS`    | A comma separated list of etcd endpoints. Example: `http://127.0.0.1:2379` (required) | string
| `etcdUsername`            | `APIV1_ETCD_USERNAME`     | User name for RBAC. Example: `user` (optional)                                        | string
| `etcdPassword`            | `APIV1_ETCD_PASSWORD`     | Password for the given user name. Example: `password` (optional)                      | string
| `etcdKeyFile`             | `APIV1_ETCD_KEY_FILE`     | Path to the etcd key file. Example: `/etc/calico/key.pem` (optional)                  | string
| `etcdCertFile`            | `APIV1_ETCD_CERT_FILE`    | Path to the etcd client certificate, Example: `/etc/calico/cert.pem` (optional)       | string
| `etcdCACertFile`          | `APIV1_ETCD_CA_CERT_FILE` | Path to the etcd Certificate Authority file. Example: `/etc/calico/ca.pem` (optional) | string

> **Note**:
> - If you are running with TLS enabled, ensure your `APIV1_ETCD_ENDPOINTS` addresses 
>   use HTTPS.
> - You can optionally prefix each environment variable with `CALICO_`. For example:
>   `CALICO_APIV1_DATASTORE_TYPE`, `CALICO_APIV1_ETCD_ENDPOINTS`. You may find this
>   useful if the non-prefixed names clash with existing environment variables.
{: .alert .alert-info}


### Configuring calico-upgrade to connect to the etcdv3 cluster

You can use either configuration files or environment variables to configure
`calico-upgrade`. It checks these in the following order of precedence.

1. **Configuration file**: The file can be in either YAML or JSON format. It 
   must be valid and readable by `calico-upgrade`. A YAML example follows.

   ```
   apiVersion: projectcalico.org/v3
   kind: CalicoAPIConfig
   metadata:
   spec:
     datastoreType: "etcdv3"
     etcdEndpoints: "http://etcd1:2379,http://etcd2:2379"
     ...
   ```

1. **Environment variables**: If `calico-upgrade` cannot locate, read, or access an 
   etcdv3 configuration file, it checks a specific set of environment variables 
   (itemized below).

The full list of possible configuration file options and environment variables follows.

| Configuration file option | Environment variable | Description                                                                           | Schema
| ------------------------- | -------------------- | ------------------------------------------------------------------------------------- | ------
| `datastoreType`           | `DATASTORE_TYPE`     | Indicates the datastore to use. Default: `etcdv3`.  (optional)                        | `etcdv3`
| `etcdEndpoints`           | `ETCD_ENDPOINTS`     | A comma separated list of etcd endpoints. Example: `http://127.0.0.1:2379` (required) | string
| `etcdUsername`            | `ETCD_USERNAME`      | User name for RBAC. Example: `user` (optional)                                        | string
| `etcdPassword`            | `ETCD_PASSWORD`      | Password for the given user name. Example: `password` (optional)                      | string
| `etcdKeyFile`             | `ETCD_KEY_FILE`      | Path to the etcd key file. Example: `/etc/calico/key.pem` (optional)                  | string
| `etcdCertFile`            | `ETCD_CERT_FILE`     | Path to the etcd client certificate, Example: `/etc/calico/cert.pem` (optional)       | string
| `etcdCACertFile`          | `ETCD_CA_CERT_FILE`  | Path to the etcd Certificate Authority file. Example: `/etc/calico/ca.pem` (optional) | string

> **Note**:
> - If you are running with TLS enabled, ensure your `ETCD_ENDPOINTS` addresses 
>   use HTTPS.
> - You can optionally prefix each environment variable with `CALICO_`. For example:
>   `CALICO_DATASTORE_TYPE`, `CALICO_ETCD_ENDPOINTS`. You may find this
>   useful if the non-prefixed names clash with existing environment variables.
{: .alert .alert-info}

## Next steps

After configuring `calico-upgrade` to communicate with the existing etcdv2 instance
and the target etcdv3 cluster, continue to [Testing the data migration](/{{page.version}}/getting-started/kubernetes/upgrade/test).