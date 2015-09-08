# Calico Networking for rkt

`calico-rkt` offers basic Calico networking for rkt deployments.

## Using rkt Plugins

The CoreOS [documentation](https://github.com/coreos/rkt/blob/master/Documentation/networking.md) for Network Plugins will walk you through the basics of setting up networking in rkt.

## Requirements

* A working [etcd](https://github.com/coreos/etcd) service
* A build of `calicoctl` after [projectcalico/calico-docker@10460cc405](https://github.com/projectcalico/calico-docker/commit/10460cc405f5aa4bc9ccb1fcaf8760088ae1ebf9)
* Though Calico is capable of networking rkt containers, our core software is distributed and deployed in a [docker container](https://github.com/projectcalico/calico-docker/blob/master/docs/getting-started/default-networking/Demonstration.md). While we work on native rkt support, you will need to run Calico in Docker before starting your rkt containers. This can be easily done wtih `calicoctl` by running the following command: `sudo calicoctl node --ip=<IP> --rkt`

## Installing

* Running `calicoctl node` with the `--rkt` flag will start the calico/node process and automatically install the plugin for you. Alternatively you can download the [plugin binary](https://github.com/projectcalico/calico-rkt/releases/) yourself and move it to the rkt plugin directory.
```
sudo mv -f ./calico_rkt /usr/lib/rkt/plugins/net/calico
```

## Building the plugin locally

To build the Calico Networking Plugin for rkt locally, clone this repository and run `make`.  This will build the binary, as well as run the unit tests.  To just build the binary, with no tests, run `make binary`.  To only run the unit tests, simply run `make ut`.

## Configuration

* Configure your network with a `*.conf` file in `/etc/rkt/net.d/`.
    - Each Network should be given a unique `"name"`
    - Each Calico Network config specifies  `"calico"` as `"type"`.
    - The `"ipam"` section must include the key `"type": "calico-ipam"` and specify an IP Pool in `"subnet"`
```
# 10-calico.conf

{
    "name": "example_net",
    "type": "calico",
    "ipam": {
        "type": "calico-ipam",
        "subnet": "10.1.0.0/16",
    }
}
```
* When you spin up a container with `rkt run`, specify the `--private-net=<NETWORK_NAME>` flag, or in the above case, `--private-net=example_net`, to apply the network config and enable Calico Networking

## Networking Behavior

In rkt deployments, Calico will allocate an available IP within the specified subnet pool and enforce the default Calico networking rules on containers. The default behavior is to allow traffic only from other containers in the network. For each network with a unique `"name"` parameter (as shown above), Calico will create a single profile that will be applied to each container added to that network.
