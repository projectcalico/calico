The following is a summary of the templates defined in this directory.

BIRD 3.x is a single unified daemon serving both IPv4 and IPv6, so each
template renders both address families into a single set of files (there are
no separate `bird6.*` files).

### bird.cfg.template

Referenced by the confd-generated bird.toml file. Renders the main BIRD
configuration: global options, the device and direct protocols, the IPv4 and
IPv6 kernel protocols, and the IPv4 and IPv6 BGP protocols (separate protocol
instances per address family). It `include`s bird_aggr.cfg and bird_ipam.cfg.

### bird_ipam.cfg.template

Referenced by bird_ipam.toml. Writes out the route filter functions
(`calico_export_to_bgp_peers_v4/v6`, `calico_kernel_programming_v4/v6`,
`apply_communities_v4/v6`, etc.) based on IPAM configuration for both address
families. Included by bird.cfg.

### bird_aggr.cfg.template

Referenced by bird_aggr.toml. Writes out the static route protocols (IPAM
block blackholes, static routes, reachable-by next hops, and IPIP tunnel
endpoint routes for recursive nexthop resolution) and the `calico_aggr_v4/v6`
aggregation functions. Included by bird.cfg.

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calicoctl/calico_node/filesystem/templates/README.md?pixel)](https://github.com/igrigorik/ga-beacon)
