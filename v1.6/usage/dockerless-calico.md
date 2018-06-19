---
title: Dockerless Calico - Manual Installation
sitemap: false 
---
Project Calico releases are primarily distributed as docker containers for quick, easy, and consistant deployment. However, it is possible to run the core Calico components directly on the host, removing the dependency on docker.

This guide will walk through how to manually create services and configurations to run Calico on Centos7 without Docker.

## WARNING: Dockerless Calico is Experimental!
Some `calicoctl` commands rely on a running `calico-node` container, and expect docker workloads. The following commands may not function properly when Calico is run directly on the host:

1. `calicoctl node status`
2. `calicoctl checksystem`
3. All `calicoctl container ...` commands.

Please raise any encountered issues, or message us on [calico-slack](https://slack.projectcalico.org/).

## Installation
1. Make changes to SELinux and QEMU config to allow VM interfaces with type='ethernet'. ([This libvirt Wiki page][libvirt-wiki] explains why these changes are required):

```shell
setenforce permissive
```

2. Edit `/etc/selinux/config` and change the `SELINUX=` line to the following:

```shell
SELINUX=permissive
```

3. Add Calico's repositories:

```shell
cat > /etc/yum.repos.d/calico.repo <<EOF
[calico]
name=Calico Repository
baseurl=http://binaries.projectcalico.org/rpm_stable/
enabled=1
skip_if_unavailable=0
gpgcheck=1
gpgkey=http://binaries.projectcalico.org/rpm/key
priority=97
EOF
```

4. Calico depends on a few EPEL packages, so be sure you have added the EPEL repos:

```shell
yum install -y epel-release
```

5. Then install calico-felix:

```shell
yum install -y calico-felix
```

6. Until calico-felix 0.3.0 is released, you'll also have to manually install a few runtime deps:

```shell
yum install -y posix-spawn python-gevent python-eventlet python-etcd
```

7. Install the additional binaries for Dockerless-calico:

```shell
# calicoctl
curl -L https://github.com/projectcalico/calico-containers/releases/download/v0.23.1/calicoctl -o /usr/local/bin/calicoctl
chmod +x /usr/local/bin/calicoctl

# bird
curl -L https://github.com/projectcalico/calico-bird/releases/download/v0.1.0/bird -o /usr/local/bin/bird
chmod +x /usr/local/bin/bird

# confd
curl -L https://github.com/projectcalico/confd/releases/download/v0.10.0-scale/confd.static -o /usr/local/bin/confd
chmod +x /usr/local/bin/confd
```

8. Install the required systemd services and confd templates:

```shell
wget https://github.com/projectcalico/calico-containers/archive/master.tar.gz
tar -xvf master.tar.gz
cd calico-containers-master
cp -R calico_node/filesystem/etc/calico/confd /etc/calico/
cp calico_node/rpm/calico-dockerless*.service /usr/lib/systemd/
systemctl enable /usr/lib/systemd/calico-dockerless*.service
```

9. Confd expects that the host system has a script called `restart-calico-confd` available in `$PATH` which can be called to restart the confd process. This is used during confd generation of bird configuration files by confd itself.

    Install the platform-specific confd restart script:

```shell
cp calico_node/rpm/restart-calico-confd /usr/local/bin
chmod +x /usr/local/bin/restart-calico-confd
```

10. Create Calico environment file at `/etc/calico/calico-environment`:

```shell
ETCD_AUTHORITY=<EtcdIP:Port>

# Set the IP that calico should run on. This will be used by confd during
# the generation of bird configuration files.
IP=<LocalIP>
```

11. Copy the sample felix config file:

```shell
cp /etc/calico/felix.cfg.example /etc/calico/felix.cfg
```

    Then, be sure to uncomment and edit `EtcdAddr` in your new `felix.cfg` file with the IP of etcd.
    >Note: You may have noticed we've stored the etcd address twice. This is required since both the `felix.service` and `calico-dockerless.service` both need to be separately pointed to etcd.

## Start Dockerless Calico
Starting Calico is as simple as turning on the calico-dockerless service:

```shell
systemctl start calico-dockerless
```

[libvirt-wiki]: https://web.archive.org/web/20160226213437/http://wiki.libvirt.org/page/Guest_won't_start_-_warning:_could_not_open_/dev/net/tun_('generic_ethernet'_interface)
