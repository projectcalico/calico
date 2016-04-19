<!--- master only -->
> ![warning](../../../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Manage `calico/node` using systemd

It is recommended to use systemd to run the `calico/node` container in production.  This directory contains a sample `systemd` unit file to manage the `calico/node` container using rkt.

### 1. Configure environment variables
To use this unit file,  first open `calico-node.service` and fill in the following environment variables to match your system:

- `ETCD_AUTHORITY`: The ip:port of your etcd cluster.
- `FELIX_ETCDADDR`: The ip:port of your etcd cluster.
- `IP`: The IPv4 address of this node.
- `IP6`: The IPv6 address of this node if one exists.  Otherwise, leave this blank.

### 2. Install the unit file

Move the unit file to `/etc/systemd/system`

```
sudo mv calico-node.service /etc/systemd/system
```

Enable the unit to start on boot.

```
sudo systemctl enable /etc/systemd/system/calico-node.service
```

Start the unit

```
sudo systemctl start calico-node.service
```

### 3. Check status
You can check the status of the service using systemctl:

```
systemctl status calico-node.service
```
> You can also use `machinectl` to manage the container.  It will have a machine name of the form `rkt-$UUID`.

You can also check the status using the `calicoctl` tool.

```
sudo calicoctl status --runtime=rkt
```

And you should see the `calico/node` container running in `rkt list`.
```
sudo rkt list
```

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/cni/rkt/systemd/README.md?pixel)](https://github.com/igrigorik/ga-beacon)
