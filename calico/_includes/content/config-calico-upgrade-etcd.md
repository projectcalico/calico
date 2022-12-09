
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
