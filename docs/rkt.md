## Calico Networking for rkt 

The CoreOS [documentation](https://github.com/coreos/rkt/blob/master/Documentation/networking.md) for Network Plugins will walk you through the basics of setting up networking in rkt.

## Requirements

* A working [etcd](https://github.com/coreos/etcd) cluster. 
* The [calicoctl]() binary.
* Though Calico is capable of networking rkt containers, our core software is distributed and deployed in a [docker container](https://github.com/projectcalico/calico-docker/blob/master/docs/getting-started/default-networking/Demonstration.md). While we work on native rkt support, you will need to run Calico in Docker before starting your rkt containers. This can be easily done wtih `calicoctl` by running the following command: `sudo calicoctl node --ip=<IP> --rkt`

## Installation 
### Install the Plugins
* `rkt` looks for CNI plugins in `/usr/bin/rkt/plugins/net`.  Running the following command will start the `calico/node` container and automatically install the Calico CNI plugin, as well as the Calico CNI IPAM plugin to that directory. 
```
sudo calicoctl node --rkt
```

### Install Network Configuration Files 

You can configure multiple networks using the CNI.  When using `rkt`, each network is represented by a configuration file in `/etc/rkt/net.d/`. Connections to a given container are only allowed from containers on the same network.  Containers on multiple networks can be accessed by containers on each network that it is connected to. 

* To define a CNI network for Calico, create a configuration file in `/etc/rkt/net.d/`.
    - Each network should be given a unique `"name"`
    - To use Calico networking, specify `"type": "calico"`
    - To use Calico IPAM, specify `"type": "calico-ipam"` in the `"ipam"` section.

For example:
```
~/$ cat /etc/rkt/net.d/10-calico.conf
{
    "name": "example_net",
    "type": "calico",
    "ipam": {
        "type": "calico-ipam",
    }
}
```

## Running containers using Calico
Now that you have installed the Calico CNI plugin and configured a network, just include the `--net=<network_name>` option when starting containers with `rkt`.  The containers will automatically be networked using Project Calico networking.

```
rkt run --net=example_net docker://busybox
```

[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-rkt/docs/rkt.md?pixel)](https://github.com/igrigorik/ga-beacon)
