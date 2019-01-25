---
title: Upgrading Calico
canonical_url: 'https://docs.projectcalico.org/v3.5/getting-started/openstack/upgrade/upgrade'
---

## {{site.prodname}} package update

This part of the upgrade procedure varies slightly according to which operating system you are using.  

- [Upgrading an OpenStack cluster based on CentOS](#upgrading-an-openstack-cluster-based-on-centos)

- [Upgrading an OpenStack cluster based on Ubuntu](#upgrading-an-openstack-cluster-based-on-ubuntu)

> **Important**: Do not use older versions of `calicoctl` after the upgrade.
> This may result in unexpected behavior and data.
{: .alert .alert-danger}


## Upgrading an OpenStack cluster based on CentOS
   
1. On all nodes, change the location of the {{site.prodname}} packages to point to the 3.x repo:

   ```
   sudo sed -i 's/calico-2.6/calico-3.1/g' /etc/yum.repos.d/calico.repo 
   ```

1. On all compute nodes, update packages:
   ```
   sudo yum update
   ```
   We recommend upgrading the whole distribution as shown here. In case you prefer to upgrade particular packages only, those needed for a {{site.prodname}} compute node are the following.
   ```
   calico-common
   calico-compute
   calico-dhcp-agent
   calico-felix
   dnsmasq
   networking-calico
   openstack-neutron
   openstack-nova-api
   openstack-nova-compute
   ```

1. Use the following command on the compute nodes to confirm that Felix has upgraded to v3.1.x.
   ```
   calico-felix --version
   ```
   It should return `v3.1.x`.

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
   ```
   calico-common
   calico-control
   networking-calico
   openstack-neutron
   ```
  
1. On all control nodes, restart `neutron-server`:
   ```
   sudo systemctl restart neutron-server
   ```
  
1. If you ran `calico-upgrade` earlier to migrate non-openstack data, on the control node run:
   ```
   calico-upgrade complete
   ```
  
1. Remove any existing `calicoctl` instances and [install the new `calicoctl`](/{{page.version}}/usage/calicoctl/install).

1. Congratulations! You have upgraded to {{site.prodname}} {{page.version}}.
      
   > **Note**: If an error occurs during the upgrade, refer to 
   > [Downgrading {{site.prodname}}](/{{page.version}}/getting-started/openstack/upgrade/downgrade).
   {: .alert .alert-info}

## Upgrading an OpenStack cluster based on Ubuntu
1. On all nodes, change the location of the {{site.prodname}} packages to point to the 3.x repo:

   ```
  sudo bash -c 'cat > /etc/apt/sources.list.d/project-calico-calico-3_1-trusty.list' << EOF
   deb http://ppa.launchpad.net/project-calico/calico-3.1/ubuntu trusty main
   # deb-src http://ppa.launchpad.net/project-calico/calico-3.1/ubuntu trusty main
   EOF
   ```

1. On all compute nodes, update packages:
   ```
   sudo apt-get update
   sudo apt-get install calico-compute calico-felix calico-common \
                        python-etcd networking-calico calico-dhcp-agent

   ```
  
1. Use the following command on the compute nodes to confirm that Felix has upgraded to v3.1.x.
   ```
   calico-felix --version
   ```

   It should return `v3.1.x`.

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
  
1. Remove any existing `calicoctl` instances and [install the new `calicoctl`](/{{page.version}}/usage/calicoctl/install).

1. Congratulations! You have upgraded to {{site.prodname}} {{page.version}}.
      
   > **Note**: If an error occurs during the upgrade, refer to 
   > [Downgrading {{site.prodname}}](/{{page.version}}/getting-started/openstack/upgrade/downgrade).
   {: .alert .alert-info}
