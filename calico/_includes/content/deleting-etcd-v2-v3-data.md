## Deleting Calico data from etcdv2 after a successful migration and upgrade

### Prerequisite

This procedure requires etcdctl v3. The etcdctl tool is installed along with etcd. To install just etcdctl, [download the etcd release binary](https://github.com/coreos/etcd/releases){:target="_blank"}, untar it, and extract the etcdctl binary.
  
### Deleting Calico data from etcdv2

> **Note**: You must pass the same options you 
> [configured `calico-upgrade` with](./setup#configuring-calico-upgrade-to-connect-to-the-etcdv2-datastore) 
> to etcdctl to achieve a connection. We include just the `--endpoint` flag in the
> following commands. Depending on your etcd configuration, you may need to include
> additional parameters in these commands. Refer to the 
> [etcdctl documentation for etcdv2 datastores](https://github.com/coreos/etcd/blob/master/etcdctl/READMEv2.md){:target="_blank"}
> for more information about the flags and environment variables.
{: .alert .alert-info}

1. Issue the following command to retrieve a list of all of the Calico keys.
   
   ```
   etcdctl --endpoint=<etcdv2-hostname:port> ls /calico --recursive
   ```
   
1. Issue the following command to delete the {{site.prodname}} keys.
   
   ```
   etcdctl --endpoint=<etcdv2-hostname:port> rm /calico/ --recursive 
   ```
   
1. Issue the following command to confirm that the {{site.prodname}} keys were deleted.
   
   ```
   etcdctl --endpoint=<etcdv2-hostname:port> ls /calico --recursive
   ```
   
   It should return `Error: 100: Key not found (/calico) [1186]`.
   
1. Congratulations! You've cleaned {{site.prodname}}'s etcdv2 datastore of {{site.prodname}}
   data. 

## Deleting Calico data from etcdv3 after a partial migration

### Prerequisites

This procedure requires etcdctl v3. The etcdctl tool is installed along with etcd. To install just etcdctl, [download the etcd release binary](https://github.com/coreos/etcd/releases){:target="_blank"}, untar it, and extract the etcdctl binary.

### Deleting Calico data from etcdv3

> **Note**: You must pass the same options you 
> [configured `calico-upgrade` with](./setup#configuring-calico-upgrade-to-connect-to-the-etcdv3-cluster) 
> to etcdctl to achieve a connection. We include just the `--endpoints` flag in the
> following commands. Depending on your etcd configuration, you may need to include
> additional parameters in these commands or set environment variables. Refer to the 
> [etcdctl documentation for etcdv3 datastores](https://github.com/coreos/etcd/blob/master/etcdctl/README.md){:target="_blank"} 
> for more information about the flags and environment variables.
{: .alert .alert-info}

1. Issue the following command to retrieve a list of all of the Calico keys.
   
   ```
   ETCDCTL_API=3 etcdctl --endpoints=<etcdv3-hostname:port> get /calico/ --prefix --keys-only
   ```
   
1. Issue the following command to delete the {{site.prodname}} keys.
   
   ```
   ETCDCTL_API=3 etcdctl --endpoints=<etcdv3-hostname:port> del /calico/ --prefix 
   ```
   
   It returns the number of keys it deleted.
   
1. Issue the following command to confirm that the {{site.prodname}} keys were deleted.
   
   ```
   ETCDCTL_API=3 etcdctl --endpoints=<etcdv3-hostname:port> get /calico/ --prefix --keys-only
   ```
   
   It should return nothing.
   
1. Congratulations! You've cleaned {{site.prodname}}'s etcdv3 datastore of {{site.prodname}}
   data. 
   
### Next steps

Return to [Migrate your data](./migrate)
to try again.
