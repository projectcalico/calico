---
title: Downgrading Calico
redirect_from: latest/getting-started/openstack/upgrade/downgrade
canonical_url: 'https://docs.projectcalico.org/v3.2/getting-started/openstack/upgrade/downgrade'
---

## About downgrading {{site.prodname}}

Under some circumstances, you may need to perform a downgrade and return your
cluster to the previous version of {{site.prodname}}. If you need to downgrade
you should do so as soon as possible to avoid an outage.

> **Important**: After downgrading or aborting the migration it is necessary
> to delete the previously migrated
> [etcd](./delete#deleting-calico-data-from-etcdv3-after-a-partial-migration)
{: .alert .alert-info}

## {{site.prodname}} package downgrade

This procedure is the reverse of the upgrade procedure and varies slightly according to which operating system you are using.  

- [Downgrading an OpenStack cluster based on CentOS](#downgrading-an-openstack-cluster-based-on-centos)

- [Downgrading an OpenStack cluster based on Ubuntu](#downgrading-an-openstack-cluster-based-on-ubuntu)

> **Important**: Do not use newer versions of `calicoctl` after the upgrade.
> This may result in unexpected behavior and data.
{: .alert .alert-danger}


## Downgrading an OpenStack cluster based on CentOS

### Downgrade {{site.prodname}} components
The remainder of the procedure is the reverse of the upgrade procedure:
   
1. Remove any upgraded `calicoctl` instances and [install the previous `calicoctl`](/{{page.version}}/usage/calicoctl/install).

1. On all nodes, change the location of the {{site.prodname}} packages to point to the 2.6.x repo:

   ```
   sudo sed -i 's/calico-3.1/calico-2.6/g' /etc/yum.repos.d/calico.repo 
   ```

1. Downgrade the Control software:
   1. On all control nodes, wipe repo data and downgrade packages:
      ```
      sudo yum clean all
      sudo yum downgrade calico-common calico-control networking-calico
      ```
      
   1. On all control nodes, restart `neutron-server`:
      ```
      sudo systemctl restart neutron-server
      ```

1. Downgrade the compute software
   
   1. On all compute nodes, remove the following line from `/etc/calico/felix.cfg`:
      ```
      DatastoreType = etcdv3
      ```
      If you changed the EtcdEndpoints address (e.g. because you installed a new etcdv3 cluster 
      rather than upgrading your existing etcdv2 cluster), you should update the EtcdEndpoints addresses 
      in `/etcd/calico/felix.cfg` at this point.
      
   1. On all compute nodes, update packages:
      ```
      sudo yum clean all
      sudo yum downgrade calico-common calico-compute calico-dhcp-agent calico-felix dnsmasq networking-calico
      ```
      
   1. Use the following command on the compute nodes to confirm that Felix has downgraded to v2.6.x.
      ```
      calico-felix --version
      ```
   
      It should return `v2.6.x`.

1. You have completed the downgrade.


## Downgrading an OpenStack cluster based on Ubuntu

1. Remove any upgraded `calicoctl` instances and [install the previous `calicoctl`](/{{page.version}}/usage/calicoctl/install).

1. On all nodes, change the location of the {{site.prodname}} packages to point to the 2.6.x repo:

   ```
   sudo rm /etc/apt/sources.list.d/project-calico-calico-3_1-trusty.list 
   ```
   
1. Downgrade the Control software:
   1. On all control nodes:
   Check the correct versions of downgraded packages with: 
      ```
      apt-cache madison calico-control calico-common python-etcd networking-calico | grep calico-2.6
      ```
      Then use the available versions listed by the above command to create a downgrade command something like this:

      ```    
      sudo apt-get install --reinstall \
        calico-control=1:1.1.2 \
        calico-common=2.6.5~trusty \
        python-etcd=0.4.3+calico.1-1 \
        networking-calico=1:1.4.3~trusty
      ```
      
   1. On all control nodes, restart `neutron-server`:
      ```
      sudo service neutron-server restart
      ```

1. Downgrade the compute software
   
   1. On all compute nodes, remove the following line from `/etc/calico/felix.cfg`:
      ```
      DatastoreType = etcdv3
      ```
      If you changed the EtcdEndpoints address (e.g. because you installed a new etcdv3 cluster 
      rather than upgrading your existing etcdv2 cluster), you should update the EtcdEndpoints addresses 
      in `/etcd/calico/felix.cfg` at this point.
   
   1. On all compute nodes:
   Check the correct versions of downgraded packages with: 
      ```
      sudo apt-get update
      apt-cache madison calico-compute calico-felix calico-common python-etcd networking-calico calico-dhcp-agent | grep calico-2.6
      ```
      Then use the available versions listed by the above command to create a downgrade command something like this:
      ```
      sudo apt-get install --reinstall \
        calico-compute=1:1.4.3~trusty \
        calico-felix=2.6.5~trusty \
        calico-common=2.6.5~trusty \
        python-etcd=0.4.3+calico.1-1 \
        networking-calico=1:1.4.3~trusty \
        calico-dhcp-agent=1:1.4.3~trusty
      ```
      
   1. Use the following command on the compute nodes to confirm that Felix has upgraded to v2.6.x.
      ```
      calico-felix --version
      ```
   
      It should return `v2.6.x`.

1. You have completed the downgrade.
