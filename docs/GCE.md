# Running calico-docker on GCE
Calico runs on the Google Compute Engine (GCE), but there are a few tweaks required to the main Getting Started instructions.
The GCE fabric itself provides L3 routing for endpoint addresses between hosts and so does not require the Calico routing function in order to provide endpoint connectivity. However, the full Calico routing and security model can be run on GCE, allowing the full power of Calico's security model on GCE (and allowing GCE to be used for testing)

## Getting started
These instructions assume a total of three GCE hosts running CoreOS. One to run an etcd "cluster", and then two compute nodes.
Documentation on running CoreOS on GCE is [here](https://coreos.com/docs/running-coreos/cloud-providers/google-compute-engine/)

Download and install GCE and login to your account. Full documentation on how to install gcloud are given [here](https://cloud.google.com/compute/docs/gcloud-compute/).
```
curl https://sdk.cloud.google.com | bash
gcloud auth login
```

Also, create a project through the GCE console and set that as the default for gcloud.
```
gcloud config set project PROJECT
```

And set a default zone
```
gcloud config set compute/zone us-central1-a
```

## Spinning up the VMs
You must make sure that the "IP forwarding" flag is set when you first configure the compute nodes (under advanced options in the web developer console, or by specifying the `--can-ip-forward` flag when creating the hosts from the command line).

Run the master with
```
gcloud compute instances create master --image https://www.googleapis.com/compute/v1/projects/coreos-cloud/global/images/coreos-alpha-618-0-0-v20150312 --machine-type g1-small --metadata-from-file user-data=cloud-config-master.yaml --can-ip-forward
```

And the compute nodes with
```
gcloud compute instances create core1 core2 --image https://www.googleapis.com/compute/v1/projects/coreos-cloud/global/images/coreos-alpha-618-0-0-v20150312 --machine-type g1-small --metadata-from-file user-data=cloud-config.yaml --can-ip-forward
```

You can get the cloud-config*.yaml files from the tests/scale directory of this repo.

## Setting up GCE networking
In order for routing to work correctly between hosts, you must notify GCE of the network address configuration you are using for your endpoints. For this demo we do this by manually running the `gcloud` utility; a production instance would almost certainly use the RESTful API. In these instructions, we'll assume that you plan on hosting addresses in the 192.168.1.0/24 range on core1, and addresses in the 192.168.2.0/24 range on core2 . The instructions for doing this are as follows.


Install each route in turn.
```
gcloud compute routes create ip-192-168-1-0 --next-hop-instance core1 --next-hop-instance-zone us-central1-a --destination-range 192.168.1.0/24
gcloud compute routes create ip-192-168-2-0 --next-hop-instance core2 --next-hop-instance-zone us-central1-a --destination-range 192.168.2.0/24
```
Note that this assumes that your hosts are called `core1` and `core2` in zone `us-central1-a`; change as appropriate for your configuration.

Now verify that you can view your instances and lists.

gcloud compute instances list
gcloud compute routes list

When you come to create endpoints (i.e. test containers) they will be able to ping one another but not do TCP or UDP because the GCE firewalls do not permit it. To enable this, add a firewall rule to allow all traffic to/from 192.168.0.0/16
```
gcloud compute firewall-rules create "any" --allow tcp:1-65535 --network "default" --source-ranges "192.168.0.0/16"
```

BIRD will not accept routes where the default gateway is not in the same subnet as the local IP on the interface, and for GCE the local IP is always a /32 (so no routes are in the same subnet). To resolve this, you must add a route that convinces BIRD that the default gateway really is valid by running a command such as that given below (where 10.240.10.1 is the IP of the server, and 10.240.0.1 is the gateway address; obviously change those for your deployment!). Note that you must do this on *both* hosts.

```
ip addr add 10.240.10.1 peer 10.240.0.1 dev ens4v1
```

There's more on this situation here, in case you want to understand this further [http://marc.info/?l=bird-users&m=139809577125938&w=2](http://marc.info/?l=bird-users&m=139809577125938&w=2)

So that BIRD is not just adding routes that have no effect (since they match the default route), we want to ban all traffic to the network that your endpoints are on. This unreachable route will be overridden when endpoints are created; on each host, the Calico Felix agent will add the route locally which will then be picked up and distributed by the BIRD clients.

```
ip route add unreachable 192.168.0.0/16
```

## Starting calico and running containers
Now, you can just follow the standard getting started instructions for downloading calico and creating workloads. See https://github.com/Metaswitch/calico-docker/blob/master/docs/GettingStarted.md#installing-calico for more details.


## (Optional) Enabling traffic from countainers to the internet
 The test endpoints will be unable to access the internet - that is because the internal range we are using is not routable. Hence to get external connectivity, SNAT is called for using the following `iptables` rule (on both hosts).

        iptables -t nat -A POSTROUTING -s 192.168.0.0/16 ! -d 192.168.0.0/16 -j MASQUERADE
