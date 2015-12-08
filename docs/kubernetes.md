## Calico Networking for Kubernetes 

## Requirements

* A working Kubernetes v1.1 cluster
* A working [etcd](https://github.com/coreos/etcd) cluster
* The [calicoctl](https://github.com/projectcalico/calico-docker/releases/latest) binary

## Installation 
### Install the Plugins
* The `kubelet` looks for CNI plugin binaries in `/opt/cni/bin`.  We'll install the Calico CNI plugin, as well as the Calico CNI IPAM plugin. 

Install the CNI plugins:
```
sudo mkdir -p /opt/cni/bin/
sudo wget -N -P /opt/cni/bin/ https://github.com/projectcalico/calico-cni/releases/download/v0.2.0/calico
sudo wget -N -P /opt/cni/bin/ https://github.com/projectcalico/calico-cni/releases/download/v0.2.0/calico-ipam
```

### Install Network Configuration Files 

We'll install the CNI network configuration file to `/etc/cni/net.d/`. Create a file called `/etc/cni/net.d/10-calico.conf` with the following contents: 
```
{
    "name": "calico-k8s-network",
    "type": "calico",
    "etcd_authority": "<host>:<port>",
    "log_level": "info",
    "ipam": {
        "type": "calico-ipam",
    }
}
```

### Start `calico/node`
The `calico/node` container runs BGP and programs iptables firewall rules. To start it:
```
sudo ETCD_AUTHORITY=<hostname>:<port> calicoctl node
```

### Configure the Kubelet
The `kubelet` must be configured to use the Calico CNI plugin.  To do this, start the kubelet with the following options:
```
--network-plugin=cni
--network-plugin-dir=/etc/cni/net.d
```

## Running Pods 
You should now be able to run Kubernetes pods using Calico networking.

You can use `calicoctl` to check the endpoints for each pod you've created:
```
export ETCD_AUTHORITY=<host>:<port>
calicoctl endpoint show --detailed
```

Plugin logs are located in `/var/log/calico/cni`, and are visible in the `kubelet` logs when `--v=5` is passed to the `kubelet`.

[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-rkt/docs/rkt.md?pixel)](https://github.com/igrigorik/ga-beacon)
