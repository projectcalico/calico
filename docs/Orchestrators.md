# Integrating Calico-Docker with an orchestrator

## Main Integration Tasks
 
 1. Calico service instantiation
     -  Instantiate an etcd cluster, ideally with proxies on each Docker compute host.
     -  Bring up one instance of the `calico-node` service on each Docker compute host in the cluster.  This is also accomplished using `calicoctl`
 2. Redirect Docker Remote API requests to `calico-node`.
    - `calico-node` exposes the Docker Remote API on port 2377, using [Powerstrip][] to trap the container create/start/stop/destroy events and program the network.
    - Pass an environment variable `CALICO_IP` with the desired container IP address during creation of the container.  _You may not specify the `--net` parameter as Calico will overwrite this._
3. After creating the container, configure profiles and Access Control Lists (ACLs) for the container by writing to the `/calico/policy/` keyspace in the etcd cluster.

[Powerstrip]: https://github.com/clusterhq/powerstrip


## Calico Services Instantiation

Install and [bootstrap etcd](https://www.youtube.com/watch?v=duUTk8xxGbU)

 - You'll want 1, 3, 5, or 7 etcd  nodes (with 3 or more [strongly recommended](https://github.com/coreos/etcd/blob/master/Documentation/admin_guide.md#optimal-cluster-size) for production environments)
 - A simple 1 node cluster can easily be installed by following the [getting started](https://github.com/coreos/etcd/releases/) instructions.
 - See the [etcd clustering guide](https://github.com/coreos/etcd/blob/master/Documentation/clustering.md) for more information on setting up a cluster. 
 - We recommend you start etcd in proxy mode on all other nodes because Calico accesses etcd on `localhost:4001` by default.
 - If you don't run the proxy, you can manually set the etcd location using the `--etcd=` option on `calicoctl` commands.  Type `calicoctl help` for details.
 

Get the calico binary onto each node:

    wget https://github.com/Metaswitch/calico-docker/releases/download/v0.4.8/calicoctl
	chmod +x calicoctl

Note that projectcalico.org is not an HA repository, so using this download URL is not recommended for any automated production installation process.  Alternatively, you can download a specific [release](https://github.com/Metaswitch/calico-docker/releases/) from github.  e.g.

	wget https://github.com/Metaswitch/calico-docker/releases/download/v0.4.8/calicoctl
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

	sudo ./calicoctl diags --upload

It prints a local file name and a URL where the diags can be downloaded from.


## Setting Calico ACLs

You can configure profiles and ACLs for Calico by directly writing to the `/calico` directory in etcd. See [etcdStructure](etcdStructure.md) for more detail. Examples of how to do this over etcd's RESTful API are given below.

### Managing Profiles

To create a profile, create the directory `/calico/policy/profile/<profile_id>/` where &lt;profile_id&gt; is a unique name for the profile.  For example, to create a `web` profile

	curl -L -X PUT http://127.0.0.1:4001/v2/keys/calico/policy/profile/web -d dir=true

To delete a profile, recursively delete the directory `/calico/policy/profile/<profile_id>/`

	curl -L -X DELETE http://127.0.0.1:4001/v2/keys/calico/policy/profile/web?recursive=true

### Defining Profile Rules

Profiles include a set of network access rules for inbound and outbound traffic for containers assigned that profile.

To manage rules, write the rules to the `/calico/policy/profile/<profile-id>/rules` key as a JSON string in the following format.

	{
	  "inbound": [{<rule>}, ...],
	  "outbound": [{<rule>}, ...]
	}

where each entry in the inbound/outbound list is a rule object:

	{
	  # Optional match criteria.  These are and-ed together.
	  "protocol": "tcp|udp|icmp|icmpv6",

	  "src_tag": "<tag name>",
	  "src_net": "<CIDR>",
	  "src_ports": [1234, "2048:4000"],  # List of ports or ranges.
	      # No artificial limit on number of ports in list.

	  # As above but for destination addr/port.
	  "dst_tag": "<tag name>",
	  "dst_net": "<CIDR>",
	  "dst_ports": [<list of ports / ranges>],

	  "icmp_type": <int>,  # Requires "protocol" to be set to an 
	      # ICMP type 

	  # Action if we match, defaults to allow, if missing.
	  "action": "deny|allow",
	} 

The rules are executed in order for each packet to/from the container.  If the packet matches a rule, the given action is executed an further rules are not executed.

For example, to allow incoming traffic on port 80 and block all other incoming traffic use the following.

	{
	  "inbound": [{"src_ports": [80], "action": "allow"},
	              {"action": "deny}],
	  "outbound": [{"action": "allow"}]
	}

Below are some more example rules:

	{"src_net": "10.65.0.0/24", "action": "allow"}

This rule matches all traffic from the 10.65.0.0/24 subnet and allows it.

	{"dst_tag": "database", "action": "allow"}

This rule matches all traffic to endpoints with the `database` tag (see next section) and allows it.

	{"protocol": "tcp", "dst_ports": [80], "action": "deny"}

This rule matches all TCP traffic to port 80 and blocks it.

### Working with Tags

A *tag* is a group or a set of Calico endpoints, and can be used as a match criterion in a rule.  You can use tags to help you manage network access permissions.  For example, lets say for a certain application there is a logging service, and both the web containers and the database containers need to be able to send it logs on port 3224.  You can create a profile for the logging service that includes an inbound rule

	{"src_tag": "logger", "protocol": "tcp", "dst_ports": [3224], "action": "allow"}
	
Then, for the web and database profiles, include `logger` in the list of tags as follows:

	curl -L -X PUT http://127.0.0.1:4001/v2/keys/calico/policy/profile/web/tags -d value=["logger"]
	curl -L -X PUT http://127.0.0.1:4001/v2/keys/calico/policy/profile/database/tags -d value=["logger"]

This will configure Calico to allow any web or database containers to access logging service containers on port 3224.

###  Assigning a profile to an endpoint.

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
			"key": "/calico/host/sjc-dev/workload/docker/fa1c1ba0b2ee300180f7400c9f385210d69f6bdc9e12defd677294fd844d680d/endpoint",
			"modifiedIndex": 132,
			"nodes": [
				{
					"createdIndex": 132,
					"dir": true,
					"key": "/calico/host/sjc-dev/workload/docker/fa1c1ba0b2ee300180f7400c9f385210d69f6bdc9e12defd677294fd844d680d/endpoint/1d9e9624cdb711e499bf08002737b14f",
					"modifiedIndex": 132
				}
			]
		}
	}

In this example, the endpoint UUID is 1d9e9624cdb711e499bf08002737b14f

The value of the endpoint UUID key is a JSON object which includes endpoint properties.

	$ curl -L http://localhost:4001/v2/keys/calico/host/sjc-dev/workload/docker/fa1c1ba0b2ee300180f7400c9f385210d69f6bdc9e12defd677294fd844d680d/endpoint/1d9e9624cdb711e499bf08002737b14f | python -m json.tool
	{
	    "action": "get",
	    "node": {
	        "createdIndex": 151,
	        "key": "/calico/host/sjc-dev/workload/docker/fa1c1ba0b2ee300180f7400c9f385210d69f6bdc9e12defd677294fd844d680d/endpoint/1d9e9624cdb711e499bf08002737b14f",
	        "modifiedIndex": 151,
	        "value": "{\"ipv6_gateway\": \"fd80:24e2:f998:72d6::1\", \"state\": \"active\", \"name\": \"cali1d9e9624cdb\", \"ipv4_gateway\": null, \"ipv6_nets\": [\"fd80:24e2:f998:72d6::1:1/128\"], \"profile_id\": null, \"mac\": \"32:24:81:2a:cb:bd\", \"ipv4_nets\": []}"
	    }
	}

To set the profile for the endpoint, modify the `profile_id` in the JSON and rewrite the value.

	$ curl -L http://localhost:4001/v2/keys/calico/host/sjc-dev/workload/docker/fa1c1ba0b2ee300180f7400c9f385210d69f6bdc9e12defd677294fd844d680d/endpoint/1d9e9624cdb711e499bf08002737b14f -XPUT -d value="{\"ipv6_gateway\": \"fd80:24e2:f998:72d6::1\", \"state\": \"active\", \"name\": \"cali1d9e9624cdb\", \"ipv4_gateway\": null, \"ipv6_nets\": [\"fd80:24e2:f998:72d6::1:1/128\"], \"profile_id\": \"web\", \"mac\": \"32:24:81:2a:cb:bd\", \"ipv4_nets\": []}"
	
(Obviously, we'd recommend you switch to using a JSON library for these manipulations in a real integration!)
