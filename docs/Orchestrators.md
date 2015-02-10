# Integrating Calico-Docker with an orchestrator

## Main Integration Tasks
 
 1. Calico service instantiation
     -  Instantiate an etcd cluster, with proxies on each Docker compute host.
     -  Bring up one instance of the `calico-master` service using `calicoctl`
     -  Bring up one instance of the `calico-node` service on each Docker compute host in the cluster.  This is also accomplished using `calicoctl`
 2. Redirect Docker Remote API requests to `calico-node`.
    - `calico-node` exposes the Docker Remote API on port 2375, using [Powerstrip][] to trap the container create/start/stop/destroy events and program the network.
    - Pass an enviroment variable `CALICO_IP` with the desired container IP address during creation of the container.  _You may not specify the `--net` parameter as Calico will overwrite this._
3. After creating the container, configure groups and Access Control Lists (ACLs) for the container by writing to the `/calico/network/` keyspace in the etcd cluster.

[Powerstrip]: https://github.com/clusterhq/powerstrip


## Calico Services Instantiation

Install and [bootstrap etcd](https://www.youtube.com/watch?v=duUTk8xxGbU)

 - You'll want 1, 3, 5, or 7 etcd  nodes (odd numbers prevent split brain)
 - If you have more compute nodes, then start etcd in proxy mode on all other nodes.  Calico needs to access etcd on `localhost:4001`
 - See the [etcd clustering guide](https://github.com/coreos/etcd/blob/master/Documentation/clustering.md).

Get the calico binary onto each node

	wget https://github.com/Metaswitch/calico-docker/releases/download/v0.0.3/calicoctl

Launch one instance of the Calico Master

	calicoctl master --ip=<IP>

Launch the Calico Node service on each Docker Host you want to use with Calico.

	calicoctl node --ip=<IP>

The “ip” parameter provides an IP on the current host on the management network that can be used.

## Launching workload containers

Workload containers are launched on the compute hosts in the cluster through either the standard docker REST API or CLI interface.

 - The `calico-node` service exposes the Docker Remote API on port 2375 using [Powerstrip][].  Use this API to start and stop containers with Calico networking.
 - The container must be launched with the CALICO_IP environment variable to assigned an IP.

For example, using the shell

	export DOCKER_HOST=localhost:2375
	docker run -e CALICO_IP=1.2.3.4 -td ubuntu

The orchestrator should then set up Access Control Lists (ACLs) as detailed below.

## Collecting diags
To collect (from the current machine only) and upload the diags, run the following command

	calicoctl diags

It prints a local file name and a URL where the diags can be downloaded from.


## Setting Calico ACLs

You can configure groups and ACLs for Calico by directly writing to the `/calico` directory in etcd.

 	+--calico  # root namespace
	   |--master
	   |  `--ip  # contains IP address of calico-master service
	   |--host
	   |  `--<hostname>  # one for each Docker host in the cluster 
	   |     |--bird_ip  # the IP address BIRD listens on
	   |     `--workload
	   |        `--docker
	   |           `--<container-id>  # one for each container on the Docker Host
	   |              `--endpoint
	   |                 `--<endpoint-id>  # UUID, only one per container in this version
	   |                    `-- (...)  # Calico endpoint info, not needed for Orchestrators
	   `--network
	      `--group
	         `--<group-id>  # UUID, one for each ACL group
	            |--name  # human readable name for the group
	            |--member  # The endpoints that are in the group.
	            |  |--<member-1>  # key is endpoint UUID, value is empty string
	            |  `--<member-2>
	            `--rule
	               |--inbound
	               |  |--1  # JSON encoded rules
	               |  `--2  
	               |--inbound_default  # only "deny" supported in this release
	               |--outbound
	               |  |--1  # JSON encoded rules
	               |  `--2  
	               `--outbound_default  # only "deny" supported in this release.

### Managing Groups

To create a group, generate a new UUID for the group.  Then set the key `/calico/network/group/<group-id>/name` to the name of the group, where &lt;group-id&gt; is the UUID you generated.

To delete a group, recursively delete the directory `/calico/network/group/<group-id>`

### Definining Group Rules

To manage Group rules, write the rules to the `/calico/network/group/<group-id>/rule/` directory as follows.

ACL rules operate on inbound and outbound traffic to and endpoint in the group.  For each direction there is a default (e.g. `./rule/inbound_default`, currently only "deny" is supported), and then 1 or more exception rules (e.g. `./rule/inbound/1`) which are JSON encoded strings with the following keys:

 - **group**: This rule allows/denies connections coming to/from a specific security group. If the "cidr" key is present, this key MUST be null.
 - **cidr**: This rule allows/denies connections coming to/from a specific subnet. If the "group" key is present, this key MUST be null.  To match all IPv4 traffic use "0.0.0.0/0".  To match all IPv6 traffic, use "::/0".
 - **protocol**: The network protocol (e.g. "udp"). To match all protocols, send null.
 - **port**: This rule only affects traffic to/from this port. Should be a JSON number, or the null (meaning all ports). Must be null for protocols that do not have ports (e.g. ICMP).

Below are some example rules:

	{"group": null, "cidr": "10.65.0.0/24", "protocol": null, "port:": null}

This rule matches all traffic to/from the 10.65.0.0/24 subnet, in all protocols, to all ports.

	{"group": "a935e8e1-008a-4e05-af4b-4b5701df417e", "cidr": null, "protocol": null, "port": null}

This rule matches all traffic to/from a specific security group.

	{"group": null, "cidr": "0.0.0.0/0", "protocol": "tcp", "port": "80"}

This rule matches all TCP traffic to/from any source to port 80.

	
###  Controlling Group Membership

After a container has been created, a node will appear in etcd

	/calico/host/<hostname>/workload/docker/<container-id>/

List the contents of `/calico/host/<hostname>/workload/docker/<container-id>/endpoint/` to get the UUID of the endpoint assigned to the container.

Then add the key `/calico/network/group/<group-id>/member/<endpoint-id>` with an empty value.

To remove an endpoint from the group, delete the corresponding key.

 
