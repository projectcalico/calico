---
title: Manage `calico/node` using systemd
canonical_url: 'https://docs.projectcalico.org/v3.6/usage/configuration/as-service'
---

It is recommended to use systemd to run the `calico/node` container in production.  Use the following [sample `systemd` unit file]({{site.baseurl}}/{{page.version}}/getting-started/rkt/vagrant/systemd/calico-node.service) to manage the `calico/node` container using rkt.

### 1. Configure environment variables
To use this unit file,  first open `calico-node.service` and fill in the following environment variables to match your system:

- `ETCD_AUTHORITY`: The ip:port of your etcd cluster.
- `FELIX_ETCDADDR`: The ip:port of your etcd cluster.
- `IP`: The IPv4 address of this node.
- `IP6`: The IPv6 address of this node if one exists.  Otherwise, leave this blank.

### 2. Install the unit file

Move the unit file to `/etc/systemd/system`

```shell
sudo mv calico-node.service /etc/systemd/system
```

Enable the unit to start on boot.

```shell
sudo systemctl enable /etc/systemd/system/calico-node.service
```

Start the unit

```shell
sudo systemctl start calico-node.service
```

### 3. Check status
You can check the status of the service using systemctl:

```shell
systemctl status calico-node.service
```
> You can also use `machinectl` to manage the container.  It will have a machine name of the form `rkt-$UUID`.

You can also check the status using the `calicoctl` tool.

```shell
sudo calicoctl status --runtime=rkt
```

And you should see the `calico/node` container running in `rkt list`.

```shell
sudo rkt list
```
