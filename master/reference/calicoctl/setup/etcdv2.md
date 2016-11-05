---
title: Configuring calicoctl - etcdv2 datastore 
layout: docwithnav
---

This document covers the configuration options for calicoctl when using an etcdv2 datastore.

## Configuration file 

By default `calicoctl` looks for a configuration file at `/etc/calico/calicoctl.cfg`.

The file location may be overridden using the `--config` option on commands that required
datastore access.

The config file is a yaml map, with the following supported fields: 

| Field           | Description                                | Examples
|-----------------|--------------------------------------------|----------
| etcdEndpoints   | A comma separated list of etcd endpoints.  | http://etcd1:2379 
| etcdUsername    | Username for RBAC (optional)               | "user" 
| etcdPassword    | Password for the given username (optional) | "password"
| etcdKeyFile     | Path to the etcd key file (optional)       | /etc/calico/key.pem
| etcdCertFile    | Path to the etcd client cert (optional)    | /etc/calico/cert.pem
| etcdCACertFile  | Path to the etcd CA file (optional)        | /etc/calico/ca.pem

> **NOTE** 
> 
> If you are running with TLS enabled, ensure your endpoint addresses use https

Each of the above configuration options can also be set through environment variables.  For example,
`etcdEndpoints` can also be represented as `ETCD_ENDPOINTS`.

#### Example configuration file

```yaml
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

