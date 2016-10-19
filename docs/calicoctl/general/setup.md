> ![warning](../../images/warning.png) This document describes an alpha release of calicoctl
>
> See note at top of [calicoctl guide](../README.md) main page.

# Setup for calicoctl
The `calicoctl` command line tool needs to be configured with details of
your datastore cluster so that it can manage system configurations and
resources.

The configuration may be specified either using a YAML or JSON input file, or through
environment variables.  Configuration is determined as follows:
-  if a configuration file is present, the file is read and that configuration
   is used, otherwise
-  if the environment variables are set, those are used, otherwise
-  a default etcdv2 endpoint at http://127.0.0.1:2379 is assumed.

Calico only supports etcd v2 as the backend datastore.  Calico supports, but does not
require:
-  role based authentication using username and password
-  certificate and key authentication.

If you need to set up role based authentication, the Configure role based access section below
describes how to set up etcd for read-only guest access, and authenticated read-write access for
a calicoctl user.

## YAML input file
By default `calicoctl` looks for a configuration file at `/etc/calico/calicoctl.cfg`.
The file location may be overridden using the `--config` option on commands that required
datastore access.

The format of the file is as follows:
```
etcdEndpoints: <ETCD ENDPOINTS>
etcdUsername: <USERNAME>
etcdPassword: <PASSWORD>
etcdKeyFile: <KEY FILE, e.g. /etc/calico/server-key.pem>
etcdCertFile: <CERT FILE e.g. /etc/calico/server.pem>
etcdCACertFile: <CA FILE e.g. /etc/calico/ca.pem>
```

The `etcdEndpoints` parameters is a comma separated list of endpoint URLs.

Replace `<...>` with appropriate values for your etcd cluster.  Username and password 
may be omitted if your etcd cluster does not require authentication. Similarly, the 
key/cert/ca file may also be omitted if your etcd server is not running in TLS mode.

If you are running in TLS mode, your endpoint addresses should be https not http.


#### Example (a cluster of 3 etcd servers with no authentication)
```
etcdEndpoints: http://myhost1:2379,http://myhost2:2379,http://myhost3:2379
```

## Environment variables
The datastore configuration may also be specified using environment variables.

Set following environment variables:
```
ETCD_ENDPOINTS=<ETCD ENDPOINTS>
ETCD_USERNAME=<USERNAME>
ETCD_PASSWORD=<PASSWORD>
ETCD_KEY_FILE=<KEY FILE, e.g. /etc/calico/server-key.pem>
ETCD_CERT_FILE=<CERT FILE e.g. /etc/calico/server.pem>
ETCD_CA_CERT_FILE=<CA FILE e.g. /etc/calico/ca.pem>
```

The `<ETCD_ENDPOINTS>` variable is a comma separated list of endpoint URLs.

Replace `<...>` with appropriate values for your etcd cluster.  Username and password 
may be omitted if your etcd cluster does not require authentication. Similarly, the 
key/cert/ca file may also be omitted if your etcd server is not running in TLS mode.

If you are running in TLS mode, your endpoint addresses should be https not http.

#### Example (set ETCD_ENDPOINTS when running calicoctl_
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

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/libcalico-go/docs/calicoctl/general/setup.md?pixel)](https://github.com/igrigorik/ga-beacon)
