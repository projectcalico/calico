---
title: Upgrade Calico on OpenStack
description: Upgrade to a newer version of Calico for OpenStack.
canonical_url: '/maintenance/openstack-upgrade'
---

## {{site.prodname}} package update

This page describes how to upgrade to {{page.version}} from {{site.prodname}} v3.0 or later. The procedure
varies by Linux distribution.

- [Upgrading an OpenStack cluster based on CentOS](#upgrading-an-openstack-cluster-based-on-centos)

- [Upgrading an OpenStack cluster based on Ubuntu](#upgrading-an-openstack-cluster-based-on-ubuntu)

> **Important**: Do not use older versions of `calicoctl` after the upgrade.
> This may result in unexpected behavior and data.
{: .alert .alert-danger}

## Upgrading an OpenStack cluster based on CentOS

1. On all nodes, change the location of the {{site.prodname}} packages to point to the {{page.version}} repo:

   ```
   sudo sed -i 's/calico-X.X/calico-Y.Y/g' /etc/yum.repos.d/calico.repo
   ```
   Replace `X.X` in the above command with the version you're upgrading from (must be v3.0 or later).
   Replace `Y.Y` with the version of the release you're upgrading to. Example: if you are upgrading from v3.1
   to v3.5, replace `X.X` with `3.1` and replace `Y.Y` with `3.5`.

1. On all compute nodes, update packages:
   ```
   sudo yum update
   ```
   We recommend upgrading the whole distribution as shown here. In case you prefer to upgrade particular packages only, those needed for a {{site.prodname}} compute node are the following.
   - `calico-common`
   - `calico-compute`
   - `calico-dhcp-agent`
   - `calico-felix`
   - `dnsmasq`
   - `networking-calico`
   - `openstack-neutron`
   - `openstack-nova-api`
   - `openstack-nova-compute`
<br><br>

1. Use the following command on the compute nodes to confirm that Felix has upgraded to {{page.version}}.
   ```
   calico-felix --version
   ```
   It should return `{{page.version}}`.

1. On all compute nodes, add the following line to the end of `/etc/calico/felix.cfg`:
   ```
   DatastoreType = etcdv3
   ```
   If you need to change the EtcdEndpoints address (e.g. because you've installed a new etcdv3 cluster
   rather than upgrading your existing etcdv2 cluster), you should update the EtcdEndpoints addresses
   in `/etcd/calico/felix.cfg` at this point.

1. On all control nodes, update packages:
   ```
   sudo yum update
   ```
   We recommend upgrading the whole distribution as shown here. In case you prefer to upgrade particular packages only, those needed for a {{site.prodname}} control node are the following.
   - `calico-common`
   - `calico-control`
   - `networking-calico`
   - `openstack-neutron`
<br><br>

1. On all control nodes, restart `neutron-server`:
   ```
   sudo systemctl restart neutron-server
   ```

1. If you ran `calico-upgrade` earlier to migrate non-openstack data, on the control node run:
   ```
   calico-upgrade complete
   ```

1. Remove any existing `calicoctl` instances and [install the new `calicoctl`](../maintenance/clis/calicoctl/install).

1. Congratulations! You have upgraded to {{site.prodname}} {{page.version}}.

## Upgrading an OpenStack cluster based on Ubuntu
1. On all nodes, change the location of the {{site.prodname}} packages to point to the {{page.version}} repo:

   ```
   sudo bash -c 'cat > /etc/apt/sources.list.d/project-calico-calico-X_X-trusty.list' << EOF
   deb http://ppa.launchpad.net/project-calico/calico-X.X/ubuntu trusty main
   # deb-src http://ppa.launchpad.net/project-calico/calico-X.X/ubuntu trusty main
   EOF
   ```
   Replace `X_X` and `X.X` with the version you're upgrading to. Example: if you're upgrading to v3.5, replace `X_X` with
   `3_5` and replace `X.X` with `3.5`. Also replace `trusty` with the code name of your Ubuntu version.

1. On all compute nodes, update packages:
   ```
   sudo apt-get update
   sudo apt-get install calico-compute calico-felix calico-common \
                        python-etcd networking-calico calico-dhcp-agent

   ```

1. Use the following command on the compute nodes to confirm that Felix has upgraded to {{page.version}}.
   ```
   calico-felix --version
   ```

   It should return `{{page.version}}`.

1. On all compute nodes, add the following line to the end of `/etc/calico/felix.cfg`:
   ```
   DatastoreType = etcdv3
   ```
   If you need to change the EtcdEndpoints address (e.g. because you've installed a new etcdv3 cluster
   rather than upgrading your existing etcdv2 cluster), you should update the EtcdEndpoints addresses
   in `/etcd/calico/felix.cfg` at this point.

1. On all control nodes, update packages:
   ```
   sudo apt-get update
   sudo apt-get install calico-control calico-common python-etcd networking-calico
   ```

1. On all control nodes, restart `neutron-server`:
   ```
   sudo service neutron-server restart
   ```

1. If you ran `calico-upgrade` earlier to migrate non-openstack data, on the control node run:
   ```
   calico-upgrade complete
   ```

1. Remove any existing `calicoctl` instances and [install the new `calicoctl`](../maintenance/clis/calicoctl/install).

1. Congratulations! You have upgraded to {{site.prodname}} {{page.version}}.
