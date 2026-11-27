$local_ip = "10.192.0.2"
$bgp_id = "10.192.0.2"
$local_asn = 64512
$peerings =
    # IPv4 is enabled on this node.
    # ------------- Node-to-node mesh -------------
    # No node-to-node mesh peers.
    # ------------- Global peers -------------
    # No global peers configured.
    # ------------- Node-specific peers -------------
    @{ Name = "Node_10_225_0_6"; IP = "10.225.0.6"; AS = 65516 },
    @{}
