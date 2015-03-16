

# etcd Directory Structure

The following illustrates the directory structure calico uses in etcd.

 	+--calico  # root namespace
 	   |--config
 	   |  |--InterfacePrefix # the prefix for Calico interface names
 	   |  `--LogSeverityFile # Log severity level for writing to file e.g. "DEBUG"
	   |--host
	   |  `--<hostname>  # one for each Docker host in the cluster
	   |     |--config  # Host level config
	   |     |  `--marker  
	   |     |--bird_ip  # the IP address BIRD listens on
	   |     |--bird6_ip  # the IP address BIRD6 listens on
	   |     `--workload
	   |        `--docker
	   |           `--<container-id>  # one for each container on the Docker Host
	   |              `--endpoint
	   |                 `--<endpoint-id>  # JSON endpoint config (see below)
	   |--policy
	   |  `--profile
	   |     `--<profile-id>  # Unique string name
	   |        |--tags  # JSON list of tags
	   |        `--rules  # JSON rules config (see below)
	   `--ipam  #IP Address Management
	      |--v4
	      |   `--pool
	      |      |--1  # CIDR range to allocate from
	      |      `--2
	      `--v6
	          `--pool
	             `--1  # CIDR range to allocate from

# JSON endpoint config

The endpoint configuration stored at 

	/calico/host/<hostname>/workload/docker/<container_id>/endpoint/<endpoint_id>

is a JSON blob in this form:

	{
	  "state": "active|inactive",  # Later, "moved" etc...
	  "name": "<name of linux interface>",
	  "mac": "<MAC of the interface>",
	  "profile_id": "<profile_id>",
	  
	  # Subnets that are owned by the endpoint, ie. that it is
	  # allowed to use as a source for its traffic.
	  "ipv4_nets": [
	    # Always expecting /32s for now but later would could allow
	    # the workload to own a subnet.
	    "198.51.100.17/32",
	    … 
	  ],
	  "ipv6_nets": [
	    # Always expecting /128s for now.
	    "2001:db8::19/128",
	    …
	  ],
	  "ipv4_gateway": "<IP address>",
	  "ipv6_gateway": "<IP address>"
	}


# JSON rules config

The rules leaf at 

	/calico/policy/profile/<profile_id>/rules

contains a JSON blob in this format

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


