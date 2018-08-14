---
title: Configuring calicoctl to connect to an etcd datastore
redirect_from: latest/usage/calicoctl/configure/etcd
canonical_url: 'https://docs.projectcalico.org/v3.1/usage/calicoctl/configure/etcd'
---

## Complete list of etcd configuration options

| Configuration file option | Environment variable | Description                                                                           | Schema
| --------------------------| -------------------- | ------------------------------------------------------------------------------------- | ------
| `datastoreType`           | `DATASTORE_TYPE`     | Indicates the datastore to use. If unspecified, defaults to `etcdv3`. (optional)      | `kubernetes`, `etcdv3`
| `etcdEndpoints`           | `ETCD_ENDPOINTS`     | A comma-separated list of etcd endpoints. Example: `http://127.0.0.1:2379,http://127.0.0.2:2379` (required) | string
| `etcdUsername`            | `ETCD_USERNAME`      | User name for RBAC. Example: `user` (optional)                                        | string
| `etcdPassword`            | `ETCD_PASSWORD`      | Password for the given user name. Example: `password` (optional)                      | string
| `etcdKeyFile`             | `ETCD_KEY_FILE`      | Path to the file containing the private key matching the `calicoctl` client certificate. Enables `calicoctl` to participate in mutual TLS authentication and identify itself to the etcd server. Example: `/etc/calicoctl/key.pem` (optional) | string
| `etcdCertFile`            | `ETCD_CERT_FILE`     | Path to the file containing the client certificate issued to `calicoctl`. Enables `calicoctl` to participate in mutual TLS authentication and identify itself to the etcd server. Example: `/etc/calicoctl/cert.pem` (optional) | string
| `etcdCACertFile`          | `ETCD_CA_CERT_FILE`  | Path to the file containing the root certificate of the certificate authority (CA) that issued the etcd server certificate. Configures `calicoctl` to trust the CA that signed the root certificate. The file may contain multiple root certificates, causing `calicoctl` to trust each of the CAs included. Example: `/etc/calicoctl/ca.pem` (optional) | string

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
> - In kubeadm deployments, {{site.prodname}} is not configured to use the etcd run by kubeadm
>   on the Kubernetes master. Instead, it launches its own instance of etcd as a pod,
>   available at `http://10.96.232.136:6666`. Ensure you are connecting to the correct etcd
>   or you will not see any of the expected data.
{: .alert .alert-info}

## Examples

#### Example configuration file

```yaml
apiVersion: projectcalico.org/v3
kind: CalicoAPIConfig
metadata:
spec:
  etcdEndpoints: https://etcd1:2379,https://etcd2:2379,https://etcd3:2379
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

## {{site.nodecontainer}}

It is important to note that not only will calicoctl will use the specified keys directly
on the host to access etcd, **it will also pass on these environment variables
and volume mount the keys into the started `{{site.noderunning}}` container.**

Therefore, configuring `{{site.nodecontainer}}` for etcd is easily accomplished by running
`calicoctl node run` with the parameters set correctly.


### Checking the configuration

Here is a simple command to check that the installation and configuration is
correct.

```
calicoctl get nodes
```

A correct setup will yield a list of the nodes that have registered.  If an
empty list is returned you are either pointed at the wrong datastore or no
nodes have registered.  If an error is returned then attempt to correct the
issue then try again.

### Next steps

Now you are ready to read and configure most aspects of {{site.prodname}}.  You can
find the full list of commands in the
[Command Reference]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/).

The full list of resources that can be managed, including a description of each,
can be found in the
[Resource Definitions]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/).
