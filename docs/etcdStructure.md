

# etcd Directory Structure

The following illustrates the directory structure calico-docker uses in etcd.

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
	   |                    |--addrs  # JSON list of [{"addr": <IP>}, ...]  (other keys in Calico API not used)
 	   |                    |--mac  # MAC address
	   |                    `--state # enabled or disabled 
	   |--network
	   |  `--group
	   |     `--<group-id>  # UUID, one for each ACL group
	   |        |--name  # human readable name for the group
	   |        |--member  # The endpoints that are in the group.
	   |        |  |--<member-1>  # key is endpoint UUID, value is empty string
	   |        |  `--<member-2>
	   |        `--rule
	   |           |--inbound
	   |           |  |--1  # JSON encoded rules
	   |           |  `--2  
	   |           |--inbound_default  # only "deny" supported in this release
	   |           |--outbound
	   |           |  |--1  # JSON encoded rules
	   |           |  `--2  
	   |           `--outbound_default  # only "deny" supported in this release.
	   `--ipam  #IP Address Management
	      |--v4
	      |   `--pool
	      |      |--1  # CIDR range to allocate from
	      |      `--2
	      `--v6
	          `--pool
	             `--1  # CIDR range to allocate from
