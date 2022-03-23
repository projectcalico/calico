---
title: Configure calicoctl to connect to an etcd datastore
description: Sample configuration files etcd.
canonical_url: '/maintenance/clis/calicoctl/configure/etcd'
---

### Big picture

Learn how to configure the calicoctl CLI tool for an etcd cluster.

### Value

The `calicoctl` CLI tool provides helpful administrative commands for interacting with a {{site.prodname}} cluster.

### Concepts

#### calicoctl vs kubectl

In previous releases, calicoctl has been required to manage Calico API resources in the `projectcalico.org/v3` API group. The calicoctl CLI tool provides important validation and defaulting on these APIs.

In newer releases, the Calico API server performs that defaulting and validation server-side, exposing the same API semantics without a dependency on calicoctl. For this reason, we recommend
[installing the Calico API server]({{site.baseurl}}/maintenance/install-apiserver.md) and using `kubectl` instead of `calicoctl` for most operations.

calicoctl is still required for the following subcommands:

- [calicoctl node]({{site.baseurl}}/reference/calicoctl/node)
- [calicoctl ipam]({{site.baseurl}}/reference/calicoctl/ipam)
- [calicoctl convert]({{site.baseurl}}/reference/calicoctl/convert)
- [calicoctl version]({{site.baseurl}}/reference/calicoctl/version)

calicoctl is also required for non-Kubernetes platforms such as OpenStack.

### How to

#### Complete list of etcd configuration options

| Configuration file option | Environment variable | Description                                                                           | Schema
| --------------------------| -------------------- | ------------------------------------------------------------------------------------- | ------
| `datastoreType`           | `DATASTORE_TYPE`     | Indicates the datastore to use. If unspecified, defaults to `kubernetes`. (optional)      | `kubernetes`, `etcdv3`
| `etcdEndpoints`           | `ETCD_ENDPOINTS`     | A comma-separated list of etcd endpoints. Example: `http://127.0.0.1:2379,http://127.0.0.2:2379` (required) | string
| `etcdDiscoverySrv`        | `ETCD_DISCOVERY_SRV` | Domain name to discover etcd endpoints via SRV records. Mutually exclusive with `etcdEndpoints`. Example: `example.com` (optional) | string
| `etcdUsername`            | `ETCD_USERNAME`      | User name for RBAC. Example: `user` (optional)                                        | string
| `etcdPassword`            | `ETCD_PASSWORD`      | Password for the given user name. Example: `password` (optional)                      | string
| `etcdKeyFile`             | `ETCD_KEY_FILE`      | Path to the file containing the private key matching the `calicoctl` client certificate. Enables `calicoctl` to participate in mutual TLS authentication and identify itself to the etcd server. Example: `/etc/calicoctl/key.pem` (optional) | string
| `etcdCertFile`            | `ETCD_CERT_FILE`     | Path to the file containing the client certificate issued to `calicoctl`. Enables `calicoctl` to participate in mutual TLS authentication and identify itself to the etcd server. Example: `/etc/calicoctl/cert.pem` (optional) | string
| `etcdCACertFile`          | `ETCD_CA_CERT_FILE`  | Path to the file containing the root certificate of the certificate authority (CA) that issued the etcd server certificate. Configures `calicoctl` to trust the CA that signed the root certificate. The file may contain multiple root certificates, causing `calicoctl` to trust each of the CAs included. Example: `/etc/calicoctl/ca.pem` (optional) | string
| `etcdKey`                 |                      | The private key matching the `calicoctl` client certificate. Enables `calicoctl` to participate in mutual TLS authentication and identify itself to the etcd server. For example, please see below.(optional) | string
| `etcdCert`                |                      | The client certificate issued to `calicoctl`. Enables `calicoctl` to participate in mutual TLS authentication and identify itself to the etcd server. For example, please see below.(optional) | string
| `etcdCACert`              |                      | The root certificate of the certificate authority (CA) that issued the etcd server certificate. Configures `calicoctl` to trust the CA that signed the root certificate. The config file may contain multiple root certificates, causing `calicoctl` to trust each of the CAs included. For example, please see below.(optional) | string

> **Note**:
> - If you are running with TLS enabled, ensure your endpoint addresses use HTTPS.
> - When specifying through environment variables, the `DATASTORE_TYPE` environment
>   is required for etcdv3.
> - All environment variables may also be prefixed with `CALICO_`, for example
>   `CALICO_DATASTORE_TYPE` and `CALICO_ETCD_ENDPOINTS` etc. may also be used.
>   This is useful if the non-prefixed names clash with existing environment
>   variables defined on your system
> - The Configuration file options `etcdCACert`, `etcdCert` and `etcdKey` does not have
>   corresponding environment variables.
> - Previous versions of `calicoctl` supported `ETCD_SCHEME` and `ETC_AUTHORITY` environment
>   variables as a mechanism for specifying the etcd endpoints. These variables are
>   no longer supported. Use `ETCD_ENDPOINTS` instead.
{: .alert .alert-info}

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
#### Example configuration file with inline CA certificate, client certificate and key

```yaml
apiVersion: projectcalico.org/v3
kind: CalicoAPIConfig
metadata:
spec:
  datastoreType: etcdv3
  etcdEndpoints: "https://127.0.0.1:2379"
  etcdCACert: |
      -----BEGIN CERTIFICATE-----
      MIICKzCCAZSgAwIBAgIBAzANBgkqhkiG9w0BAQQFADA3MQswCQYDVQQGEwJVUzER
      MA8GA1UEChMITmV0c2NhcGUxFTATBgNVBAsTDFN1cHJpeWEncyBDQTAeFw05NzEw
      MTgwMTM2MjVaFw05OTEwMTgwMTM2MjVaMEgxCzAJBgNVBAYTAlVTMREwDwYDVQQK
      EwhOZXRzY2FwZTENMAsGA1UECxMEUHViczEXMBUGA==
      -----END CERTIFICATE-----
  etcdCert: |
      -----BEGIN CERTIFICATE-----
      gI6iLXgMsp2EOlD56I6FA1jrCtNb01XQvX3eyFuA6g5T1jWGYBDtvQb0WRVkdUy9
      L/uK+sHQwtloCSuakcQAsWV9bajCQtHX8XGu25Yz56kpJ/OJjcishxT6pc/sthum
      A5PX739JsNUi/p5aG+H/6eNx+ukJP7QaM646YCfS5i8S9DJUvim+/BSlKi2ZiOCd
      0MYH4Xb7lmAOTNmTvSYpKo9J2fZ9erw0MYSBTyjh6F7PRbHBiivgUnJfGQ==
      -----END CERTIFICATE-----
  etcdKey: |
      -----BEGIN RSA PRIVATE KEY-----
      k0dWj16h9P6TvfcNl2iwT4VIwx0uy2faWBED1DrCJcuQCy5nPrts2ZIaAWPi1t3t
      VbDKQvs+KXBEeqh0qYcYkejUXqIF0uKUFLjiQmZssjpL5RHqqWuYKbO87n+Jod1L
      TjGRHdbP0zF2U0LdjM17rc2hpJ3qrmgJ7pOLzbXMcOr+NP1ojRCArXhQ4iLs7D8T
      eHw9QH4luJYtnmk7x03izLMQdLWcKnUbqh/xOVPyazgJHXwRxwNXpMsBVGY=
      -----END RSA PRIVATE KEY-----
```

#### Example using environment variables

```bash
ETCD_ENDPOINTS=http://myhost1:2379 calicoctl get bgppeers
```

#### Example using etcd DNS discovery

```bash
ETCD_DISCOVERY_SRV=example.com calicoctl get nodes
```

#### Example using IPv6

Create a single node etcd cluster listening on IPv6 localhost `[::1]`.

```bash
etcd --listen-client-urls=http://[::1]:2379 --advertise-client-urls=http://[::1]:2379
```

Use the etcd IPv6 cluster:

```bash
ETCD_ENDPOINTS=http://[::1]:2379 calicoctl get bgppeers
```

#### Example using mixed IPv4/IPv6

Create a single node etcd cluster listening on IPv4 and IPv6 localhost `[::1]`.

```bash
etcd --listen-client-urls=http://[::1]:2379,http://127.0.0.1:2379 --advertise-client-urls=http://[::1]:2379
```

Use the IPv6 endpoint:

```bash
ETCD_ENDPOINTS=http://[::1]:2379 calicoctl get bgppeers
```

Use the IPv4 endpoint:

```bash
ETCD_ENDPOINTS=http://127.0.0.1:2379 calicoctl get bgppeers
```

#### {{site.nodecontainer}}

It is important to note that not only will calicoctl will use the specified keys directly
on the host to access etcd, **it will also pass on these environment variables
and volume mount the keys into the started `{{site.noderunning}}` container.**

Therefore, configuring `{{site.nodecontainer}}` for etcd is easily accomplished by running
`calicoctl node run` with the parameters set correctly.


#### Checking the configuration

Here is a simple command to check that the installation and configuration is
correct.

```bash
calicoctl get nodes
```

A correct setup will yield a list of the nodes that have registered.  If an
empty list is returned you are either pointed at the wrong datastore or no
nodes have registered.  If an error is returned then attempt to correct the
issue then try again.

### Next steps

Now you are ready to read and configure most aspects of {{site.prodname}}.  You can
find the full list of commands in the
[Command Reference]({{ site.baseurl }}/reference/calicoctl/overview).

The full list of resources that can be managed, including a description of each,
can be found in the
[Resource Definitions]({{ site.baseurl }}/reference/resources/overview).
