---
title: Configuring calicoctl - etcdv2 datastore 
layout: docwithnav
---

This document covers the configuration options for calicoctl when using an etcdv2 datastore.

There are two ways to configure calicoctl with your etcdv2 cluster details: 
configuration file or environment variables.

## Configuration file 

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

>  Note that if neither file nor environment variables are set, calicoctl defaults to
>  using etcdv2 with a single endpoint of http://127.0.0.1:2379.

## Complete list of etcdv2 connection configuration

| Spec field      | Environment       | Description                                | Examples
|-----------------|----------------------------------------------------------------|----------
| datastoreType   | DATASTORE_TYPE    | Indicates the datastore to use (optional, defaults to etcdv2) | etcdv2
| etcdEndpoints   | ETCD_ENDPOINTS    | A comma separated list of etcd endpoints (optional, defaults to http://127.0.0.1:2379) | http://etcd1:2379 
| etcdUsername    | ETCD_USERNAME     | Username for RBAC (optional)               | "user" 
| etcdPassword    | ETCD_PASSWORD     | Password for the given username (optional) | "password"
| etcdKeyFile     | ETCD_KEY_FILE     | Path to the etcd key file (optional)       | /etc/calico/key.pem
| etcdCertFile    | ETCD_CERT_FILE    | Path to the etcd client cert (optional)    | /etc/calico/cert.pem
| etcdCACertFile  | ETCD_CA_CERT_FILE | Path to the etcd CA file (optional)        | /etc/calico/ca.pem

> **NOTES** 
> 
> 1. If you are running with TLS enabled, ensure your endpoint addresses use https
> 2. When specifying through environment variables, the DATASTORE_TYPE environment
>    is not required for etcdv2.
> 3. All environment variables may also be prefixed with "CALICO_", for example 
>    "CALICO_DATASTORE_TYPE" and "CALICO_END_ENDPOINTS" etc. may also be used.
> 4. Previous versions of calicoctl supported ETCD_SCHEME and ETC_AUTHORITY environment
>    variables as a mechanism for specifying the etcd endpoints.  These variables are
>    deprecated in favor of the ETCD_ENDPOINTS list.

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

# Additional information

## Configure role based access for etcd v2

The section describes how to configure your etcd v2 cluster to have role-based access 
control to require password authentication when modifying calico configuration.  This covers:

- Creating a read/write user for modification of Calico configuration
- Setting up the guest user (no authentication) for read-only access
- Creating a full access root user
- Turnin on role based access control

For more details, see the main etcd documentation.

To configure the roles in etcd, we use the etcdctl command line tool - 
this is packaged up alongside the etcd binary downloads.

### Configure roles

#### Read-write calico configuration

Create a write role that allows full read/write access of the calico portion of the etcd tree

```
$ etcdctl role add calico-readwrite
$ etcdctl role grant calico-readwrite -path '/calico' -readwrite
$ etcdctl role grant calico-readwrite -path '/calico/*' -readwrite
```

#### Revoke write access for the guest user

Revoke write access for the guest user.  This means the non-authenticated user of
the etcd cluster will have read-only access.

```
$ etcdctl role revoke guest -path '/*' -write
```

### Configure users

#### Configure calicooctl user
Create a calicoctl user and enter your chosen password.

```
$ etcdctl user add calicoctl
New password:
```

#### Assign the calicoctl role to this user

```
$ etcdctl user grant calicoctl -roles calico-readwrite
```

#### Create the root user
Before enabling authentication, it is also necessary to create a root user for the
cluster.  

Create the root user and enter your chosen password

```
$ etcdctl user add root 
New password:
```

### Enable authentication

Finally enable authentication

```
$ etcdctl auth enable
```

Your etcd is now running with authentication enabled. To disable it for any reason, 
use the reciprocal command:

```
$ etcdctl -u root:<rootpw> auth disable
```

### Configuring calicoctl to use authenticated etcd access
To allow calicoctl to use the new calicoctl user, ensure you specify the username 
and password either in environment variables or in the calicoctl config file as 
described above.

