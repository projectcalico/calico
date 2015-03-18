# Integrating Calico-Docker with an orchestrator

## Main Integration Tasks
 
 1. Calico service instantiation
     -  Instantiate an etcd cluster, with ideally with proxies on each Docker compute host.
     -  Bring up one instance of the `calico-node` service on each Docker compute host in the cluster.  This is also accomplished using `calicoctl`
 2. Redirect Docker Remote API requests to `calico-node`.
    - `calico-node` exposes the Docker Remote API on port 2377, using [Powerstrip][] to trap the container create/start/stop/destroy events and program the network.
    - Pass an enviroment variable `CALICO_IP` with the desired container IP address during creation of the container.  _You may not specify the `--net` parameter as Calico will overwrite this._
3. After creating the container, configure groups and Access Control Lists (ACLs) for the container by writing to the `/calico/network/` keyspace in the etcd cluster.

[Powerstrip]: https://github.com/clusterhq/powerstrip


## Calico Services Instantiation

Install and [bootstrap etcd](https://www.youtube.com/watch?v=duUTk8xxGbU)

 - You'll want 1, 3, 5, or 7 etcd  nodes (with 3 or more [strongly recommended](https://github.com/coreos/etcd/blob/master/Documentation/admin_guide.md#optimal-cluster-size) for production environments)
 - A simple 1 node cluster can easily be installed by following the [getting started](https://github.com/coreos/etcd/releases/) instructions.
 - See the [etcd clustering guide](https://github.com/coreos/etcd/blob/master/Documentation/clustering.md) for more information on setting up a cluster. 
 - We recommend you start etcd in proxy mode on all other nodes because Calico accesses etcd on `localhost:4001` by default.
 - If you don't run the proxy, you can manually set the etcd location using the `--etcd=` option on `calicoctl` commands.  Type `calicoctl help` for details.
 

Get the calico binary onto each node. It's usually safe to just grab the latest [release](https://github.com/Metaswitch/calico-docker/releases/) e.g.

	wget https://github.com/Metaswitch/calico-docker/releases/download/v0.0.6/calicoctl
	chmod +x calicoctl

Launch the Calico Node service on each Docker Host you want to use with Calico.

	sudo ./calicoctl node --ip=<IP>

The “ip” parameter provides an IP on the current host on the management network that can be used.

## Launching workload containers

Workload containers are launched on the compute hosts in the cluster through either the standard docker REST API or CLI interface.

 - The `calico-node` service exposes the Docker Remote API on port 2377 using [Powerstrip][].  Use this API to start and stop containers with Calico networking.
 - The container must be launched with the CALICO_IP environment variable to assigned an IP.

For example, using the shell

	export DOCKER_HOST=localhost:2377
	docker run -e CALICO_IP=1.2.3.4 -td ubuntu

The orchestrator should then set up Access Control Lists (ACLs) as detailed below.

## Networking existing workloads

If you need to add Calico networking to containers already created on the Docker Host, or need Calico networking to coexist with the standard Docker Bridge network, you can use the `container add` command.  For example, to add Calico networking to an existing container named `existing_newton` using `IP 192.168.1.32`

	sudo ./calicoctl container add existing_newton 192.168.1.32

This will set up Calico networking in the container's namespace as `eth1` with the configured IP address, as well as install a default route via this interface.

Please note that in this set up, Calico's ACLs will only be asserted against the Calico network interface.  For example, if you use the Docker Bridge network as the other interface, containers on the same Docker Host may communicate with one another even if the Calico ACLs would otherwise prevent this.

## Collecting diags
To collect (from the current machine only) and upload the diags, run the following command

	sudo ./calicoctl diags

It prints a local file name and a URL where the diags can be downloaded from.


## Setting Calico ACLs

You can configure groups and ACLs for Calico by directly writing to the `/calico` directory in etcd. See [etcdStructure](etcdStructure.md) for more detail. Examples of how to do this over etcd's RESTful API are given below.

### Managing Groups

To create a group, generate a new UUID for the group.  Then set the key `/calico/network/group/<group-id>/name` to the name of the group, where &lt;group-id&gt; is the UUID you generated.

	web_group=`cat /proc/sys/kernel/random/uuid`
	curl -L -X PUT http://127.0.0.1:4001/v2/keys/calico/network/group/$web_group/name -d value="Web Servers"

To delete a group, recursively delete the directory `/calico/network/group/<group-id>`

	curl -L -X DELETE http://127.0.0.1:4001/v2/keys/calico/network/group/$web_group?recursive=true

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

### Group rules worked example.

The following commands will create a group that can receive traffic only from its own members.

Create the group.

	group1=`cat /proc/sys/kernel/random/uuid`
	curl -L -X PUT http://127.0.0.1:4001/v2/keys/calico/network/group/$group1/name -d value="Group 1"

Set the default inbound rule.

	curl -L -X PUT http://127.0.0.1:4001/v2/keys/calico/network/group/$group1/rule/inbound_default -d value="deny"

Allow inbound traffic from the group (note the escaping required since we need the shell to expand $group1).

	curl -L -X PUT http://127.0.0.1:4001/v2/keys/calico/network/group/$group1/rule/inbound/1 -d value="{\"group\": \"$group1\", \"cidr\": null, \"protocol\": null, \"port\": null}"

Set the default outbound rule.

	curl -L -X PUT http://127.0.0.1:4001/v2/keys/calico/network/group/$group1/rule/outbound_default -d value="deny"

Allow outbound traffic to any IPv4 address (in this example we enclose JSON in `'`, so escaping the `"`is not required).

	curl -L -X PUT http://127.0.0.1:4001/v2/keys/calico/network/group/$group1/rule/outbound/1 -d value='{"group": null, "cidr": "0.0.0.0/0", "protocol": null, "port": null}'


###  Controlling Group Membership

After a container has been created, a node will appear in etcd

	/calico/host/<hostname>/workload/docker/<container-id>/

List the contents of `/calico/host/<hostname>/workload/docker/<container-id>/endpoint/` to get the UUID of the endpoint assigned to the container.

	export DOCKER_HOST=localhost:2377
	container1=`docker run -e CALICO_IP 192.168.0.101 -td ubuntu`
	curl -L http://127.0.0.1:4001/v2/keys/calico/host/$HOSTNAME/workload/docker/$container1/endpoint
	
If you have python available on your system, you can use it format JSON returned by etcd.

	curl -L http://127.0.0.1:4001/v2/keys/calico/host/$HOSTNAME/workload/docker/$container1/endpoint | python -m json.tool
	
Example output:

	{
		"action": "get",
		"node": {
			"createdIndex": 132,
			"dir": true,
			"key": "/calico/host/sjc-dev/workload/docker/b41eb37fae7f7bf3388e0565e1a1d014fba239424b7ca1d81b2139d54c2260cd/endpoint",
			"modifiedIndex": 132,
			"nodes": [
				{
					"createdIndex": 132,
					"dir": true,
					"key": "/calico/host/sjc-dev/workload/docker/b41eb37fae7f7bf3388e0565e1a1d014fba239424b7ca1d81b2139d54c2260cd/endpoint/97753abeb0bd11e49cac08002737b14f",
					"modifiedIndex": 132
				}
			]
		}
	}

In this example, the endpoing UUID is 97753abeb0bd11e49cac08002737b14f

To add an endpoint to a group, create the key `/calico/network/group/<group-id>/member/<endpoint-id>` with an empty value.  Using `$group1` from the above example:

	curl -L -X PUT http://127.0.0.1:4001/v2/keys/calico/network/group/$group1/member/97753abeb0bd11e49cac08002737b14f -d value=''

To remove an endpoint from the group, delete the corresponding key.

	curl -L -X DELETE http://127.0.0.1:4001/v2/keys/calico/network/group/$group1/member/97753abeb0bd11e49cac08002737b14f
 
