$local_ip = "10.192.0.2"
$bgp_id = "10.192.0.2"
$local_asn = 64512
$peerings =
    # IPv4 is enabled on this node.
    # ------------- Node-to-node mesh -------------
    @{ Name = "Mesh_10_192_0_3"; IP = "10.192.0.3"; AS = 64512 },
    @{ Name = "Mesh_10_192_0_4"; IP = "10.192.0.4"; AS = 64513 },
    # ------------- Global peers -------------
    # No global peers configured.
    # ------------- Node-specific peers -------------
    @{ Name = "Node_10_225_0_6"; IP = "10.225.0.6"; AS = 65516 },
    @{}
