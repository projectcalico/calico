<!--- master only -->
> ![warning](images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# etcd Directory Structure

The following illustrates the directory structure calico uses in etcd.
    
    +--calico  # root namespace
       |
       |--v1
       |  |--config
       |  |  |--LogFilePath       # the file path for the felix log file.
       |  |  |--IpInIpEnabled     # whether IPIP is enabled
       |  |  |--LogSeverityScreen # the log severity for logs written to stdout/stderr
       |  |  |--InterfacePrefix   # the prefix for Calico interface names
       |  |  |--LogSeverityFile   # Log severity level for writing to file e.g. "DEBUG"
       |  |  `-- ... # Other Felix options are available, and many of these options
       |  |          # can be specified as host-specific.  For details, read the following:    
       |  |          #   http://docs.projectcalico.org/en/latest/configuration.html    
       |  |--host
       |  |  `--<hostname>      # one for each Docker host in the cluster
       |  |     |--config       # Host level config
       |  |     |  `--marker
       |  |     |--bird_ip      # the host IP (IPv4) [to be retired]
       |  |     `--workload
       |  |        `--docker
       |  |           `--<container-id>  # one for each container on the Docker Host
       |  |              `--endpoint
       |  |                 `--<endpoint-id>  # JSON endpoint config (see below)
       |  |--policy
       |  |  `--profile
       |  |     `--<profile-id>  # Unique string name
       |  |        |--tags  # JSON list of tags
       |  |        `--rules  # JSON rules config (see below)
       |  `--ipam  # IP Pool configuration
       |     |--v4
       |     |   `--pool
       |     |      `--<CIDR>  # One per pool, key is CIDR with '/' replaced
       |     |                 # by '-', value is JSON IP Pool object (see below)
       |     `--v6
       |         `--pool
       |            `--<CIDR>  # One per pool, key is CIDR with '/' replaced
       |                       # by '-', value is JSON IP Pool object (see below)
       |--ipam/v2 # IPAM configuration and assignment data
       |  |--assignment
       |  |  |--ipv4
       |  |  |  `--block
       |  |  |      `--<CIDR>  # One per block, key is CIDR with '/' replaced
       |  |  |                 # by '-', value is JSON Allocation Block object (see below)
       |  |  `--ipv6  
       |  |     `--block
       |  |         `--<CIDR>  # One per block, key is CIDR with '/' replaced
       |  |                    # by '-', value is JSON Allocation Block object (see below)
       |  |--handle
       |  |  `--<Handle ID>    # One per handle, value is JSON Allocation Handle
       |  |                    # object (see below)
       |  |--host
       |  |  `--<hostname>
       |  |     |--ipv4
       |  |     |  `--block
       |  |     |     `--<CIDR>   # CIDR matching the Allocation Block with this host
       |  |     |                 # affinity.  No value stored.
       |  |     `--ipv6  
       |  |     |  `--block
       |  |     |     `--<CIDR>   # CIDR matching the Allocation Block with this host
       |  |     |                 # affinity.  No value stored.
       `--bgp/v1  # BGP Configuration
          |--global
          |  |--as_num    # the default BGP AS number for the nodes
          |  |--node_mesh # JSON node-to-node mesh configuration (see below)
          |  |--peer_v4   # Global IPv4 BGP peers (all nodes peer with)
          |  |  `--<BGP peer IPv4 address>  # JSON BGP peer configuration (see below)
          |  `--peer_v6   # Global IPv6 BGP peers (all nodes peer with)
          |     `--<BGP peer IPv6 address>  # JSON BGP peer configuration (see below)
          `--host
             `--<hostname>  # one for each Docker host in the cluster
                |--ip_addr_v4 # the IP address BIRD listens on
                |--ip_addr_v6 # the IP address BIRD6 listens on
                |--as_num     # the AS number for this host
                |--peer_v4    # Host specific IPv4 BGP peers
                |  `--<BGP peer IPv4 address>  # JSON BGP peer configuration (see below)
                `--peer_v6  # Host specific IPv6 BGP peers
                   `--<BGP peer IPv6 address>  # JSON BGP peer configuration (see below)


## JSON endpoint configuration

The endpoint configuration stored at 

    /calico/v1/host/<hostname>/workload/docker/<container_id>/endpoint/<endpoint_id>

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

## JSON rules configuration

The rules leaf at 

    /calico/v1/policy/profile/<profile_id>/rules

contains a JSON blob in this format

    {
      "inbound_rules": [{<rule>}, ...],
      "outbound_rules": [{<rule>}, ...]
    }

where each entry in the inbound_rules/outbound_rules list is a rule object:

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
      "action": "deny|allow"
    } 

## JSON IP pool configuration

The IP pool configuration stored at

    /calico/v1/ipam/v4/pool/<CIDR> and
    /calico/v1/ipam/v6/pool/<CIDR>

is a JSON blob in this form:

    {
      "cidr": "<CIDR of pool - eg. 192.168.0.0/16 or fd80:24e2:f998:72d6::/64>",
      "ipip": "<IPIP device name if IPIP configured for the pool - usually tunl0>",
      "masquerade": true|false
    }

The ipip field is only included if IPIP is enabled for this pool.  IPIP is only supported on IPv4 pools.  

The masquerade field enables NAT for outbound traffic.  If omitted, masquerade defaults to false.

## JSON Allocation Block configuration

The Allocation Block configuration stored at

    ipam/v2/assignment/ipv4/block/<CIDR> and
    ipam/v2/assignment/ipv6/block/<CIDR> and

is a JSON blob in this form:

    {
        "cidr": "192.168.0.0/24",
        "affinity": "host:calico-host-01",
        "allocations": [0, 0, 0, 1, 2, 2, nil, nil, nil, nil, ...],
        "attributes": [
            {
                "primary": "0cd47986-24ad-4c00-b9d3-5db9e5c02028",
                "secondary": {
                    "container-id": "ba11f1de-fc4d-46fd-9f15-424f4ef05a3a",
                    "email": "spike@projectcalico.org"
                }
            },
            {
                "primary": "3465987ac-8975-987qr8789725875-98275",
                "secondary": {
                    "container-name": "sandy_sabin",
                    "email": "spike@projectcalico.org"
                }
            },
            {
                "primary": "adf4589-11ab-c519-af11-098fade2190798",
                "secondary": {
                    "rack": "01"
                }
            }
        ] 
    }

where

-  *cidr* - The block prefix in CIDR format.
-  *affinity* - The host with affinity to this block.
-  *allocations* - A fixed length array with one entry for every address in the
   block.  Nil means unallocated.  A non-negative integer indicates the address
   is allocated, and is the index into the attributes array for the attributes
   assigned to the allocation.
-  *attributes* - List of dictionaries of attributes for allocations.
   
## JSON Allocation Handles configuration

The Allocation Handle configuration stored at

    ipam/v2/assignment/handle/<Handle ID>

is a JSON blob in this form:

    {
        "id": <string handle ID>,
        "block": {
            "192.168.10.0/24": 4,
            "2001:abcd:def0::/120": 3
        }
    }

where

-  *id* - The handle ID
-  *block* - A dictionary mapping Allocation Block CIDRs with the count of
   allocations within that block associated with this handle.


## JSON node-to-node mesh configuration

The configuration controlling whether a full node-to-node BGP mesh is set up
automatically.

The node-to-node mesh configuration stored at

    /calico/v1/config/bgp_node_mesh

is a JSON blob in this form:

    {
      "enabled": true|false
    }

If the key is missing from etcd, the node-to-node mesh is enabled by default.

## JSON BGP Peer configuration

Explicit BGP peers are configurable globally (all hosts peer with these), or
for a specific host.

The full set of peers for a specific host comprises all other hosts (if the
node-to-node mesh is enabled), the set of global peers and the set of peers
specific to the host.

The configuration for the global BGP peers is stored at

    /calico/v1/config/bgp_peer_v4/<BGP peer IPv4 address>

and

    /calico/v1/config/bgp_peer_v6/<BGP peer IPv6 address>


The configuration for the host node specific BGP peers is stored at

    /calico/v1/host/<hostname>/bgp_peer_v4/<BGP peer IPv4 address>

and

    /calico/v1/host/<hostname>/bgp_peer_v6/<BGP peer IPv6 address>

In all cases, the data is a JSON blob in the form:

    {
      "ip": "IP address of BGP Peer",
      "as_num": "The AS Number of the peer"
    }

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/etcdStructure.md?pixel)](https://github.com/igrigorik/ga-beacon)
