# Running calico-docker on GCE
Calico runs on the Google Compute Engine (GCE), but there are a few tweaks required to the main Getting Started instructions.  The following instructions show the full power of the Calico routing and security model on GCE (and allow GCE to be used for testing)

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
In order for routing to work correctly between hosts, you must set up a firewall rule on GCE to allow IPIP packets to flow between the instances. The command for doing this are as follows.

```
gcloud compute firewall-rules create calico-ipip --allow 4 --network "default" --source-ranges "10.240.0.0/16"
```
Now verify that you can view your instances and firewall rule.
```
gcloud compute instances list
gcloud compute firewall-rules list
```

BIRD will not accept routes where the default gateway is not in the same subnet as the local IP on the interface, and for GCE the local IP is always a /32 (so no routes are in the same subnet). To resolve this, you must add a route that convinces BIRD that the default gateway really is valid by running a command such as that given below (where 10.240.10.1 is the IP of the server, and 10.240.0.1 is the gateway address; obviously change those for your deployment!). Note that you must do this on *both* hosts.

```
ip addr add 10.240.10.1 peer 10.240.0.1 dev ens4v1
```

There's more on this situation here, in case you want to understand this further [http://marc.info/?l=bird-users&m=139809577125938&w=2](http://marc.info/?l=bird-users&m=139809577125938&w=2)

## Starting calico and running containers
Now, you can just follow the standard getting started instructions for downloading calico and creating workloads. See https://github.com/Metaswitch/calico-docker/blob/master/docs/GettingStarted.md#installing-calico for more details.

Note that etcd should already be running on the master, core1 and core2 nodes, with data stored on the master node, and core1 and core2 run etcd in proxy mode, so no clustering is required.  Check this by running ```etcdctl ls /``` on each node.  If it is not running, then restart it by running ```docker start etcd```.

## (Optional) Enabling traffic from containers to the internet
The test endpoints will be unable to access the internet - that is because the internal range we are using is not routable. Hence to get external connectivity, SNAT is called for using the following `iptables` rule (on both hosts).

```
iptables -t nat -A POSTROUTING -s 192.168.0.0/16 ! -d 192.168.0.0/16 -j MASQUERADE
```

## (Optional) Enabling traffic from the internet to containers
Services running on containers in GCE can be exposed to the internet using Calico using port mapping iptables NAT rules and an appropriate Calico security profile.  For example, you have a container that you've assigned the CALICO_IP of 192.168.7.4 to, and you have NGINX running on port 80 inside the container. If you want to expose this on port 8000, then you should follow the instructions at https://github.com/Metaswitch/calico-docker/blob/master/docs/AdvancedNetworkPolicy.md to expose port 80 on the container and then run the following command to add the port mapping:

```
iptables -A PREROUTING -t nat -i ens4v1 -p tcp --dport 8000 -j DNAT  --to 172.168.7.4:80
```
