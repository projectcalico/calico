# confd glossary

This file extends the [root GLOSSARY.md](../GLOSSARY.md). confd renders the BIRD configuration templates, so the words for BIRD configuration are here too, even though the template files live under `node/filesystem/`. Routing words shared with Felix (cluster route, node-to-node mesh, route reflector) are defined in the root file.

## Building blocks

Top layer of confd.

| Building block | Code | Responsible for |
|---|---|---|
| Calico store client | `confd/pkg/backends/calico/client.go` (`client`) | Turning BGP syncer updates into a flat key and value cache, with a revision counter, that the templates read. |
| BGP config processor | `confd/pkg/backends/calico/bgp_processor.go` (`GetBirdBGPConfig`) | Building the per-IP-family `BirdBGPConfig`: peers, filters, communities and pool statements. |
| v1 peering computation | `confd/pkg/backends/calico/client.go` (`updatePeersV1`) | Expanding BGPPeer resources, with selectors and reverse peerings, into peering keys in the cache. |
| Route generator | `confd/pkg/backends/calico/routes.go` (`routeGenerator`) | Watching Services and EndpointSlices and advertising per-service routes from this node. |
| Local BGP peer watcher | `confd/pkg/backends/calico/local_bgp_peer_watcher.go` (`LocalBGPPeerWatcher`) | Reading endpoint status files to find the workloads that should be BGP peers. |
| Template processor | `confd/pkg/resource/template/processor.go` (`watchProcessor`) | Re-rendering each template resource when its watched keys change. |
| BIRD config files | `node/filesystem/etc/calico/confd/templates/bird.cfg.template` | The templates confd renders: `bird.cfg`, `bird_ipam.cfg`, `bird_aggr.cfg` and their IPv6 counterparts. |

Layers inside the BGP config processor, the client and the BIRD config files.

| Building block | Code | Responsible for |
|---|---|---|
| Pool processing | `confd/pkg/backends/calico/bgp_processor.go` (`processIPPools`) | Emitting the per-pool BIRD filter statements for kernel programming and BGP export. |
| Cluster-route policy | `confd/pkg/backends/calico/bgp_processor.go` (`clusterRoutePolicy`) | Recording which pool encapsulation modes BIRD programs cluster routes for. |
| Peer processing | `confd/pkg/backends/calico/bgp_processor.go` (`processPeers`, `processMeshPeers`, `buildPeerFromData`) | Turning the mesh, global, node-specific and local workload peers into `BirdBGPPeer` entries. |
| WireGuard peer filter | `confd/pkg/backends/calico/bgp_processor.go` (`processWireguardPeerFilter`) | Rejecting kernel routes whose next hop is a WireGuard-enabled peer. |
| Global service routes | `confd/pkg/backends/calico/client.go` (`updateGlobalRoutes`, `RouteIndex`) | Adding the BGPConfiguration service CIDRs as advertised service routes and kernel-reject CIDRs. |
| Secret watcher | `confd/pkg/backends/calico/secret_watcher.go` (`secretWatcher`) | Watching the Kubernetes Secrets that hold BGP passwords. |
| Node label manager | `confd/pkg/backends/calico/node_labels.go` (`nodeLabelManager`) | Caching node labels to evaluate a BGPPeer's `nodeSelector` and `peerSelector`. |
| Template resource | `confd/pkg/resource/template/resource.go` (`TemplateResource`) | Staging a rendered file, checking it, swapping it in, then reloading BIRD. |
| Template functions | `confd/pkg/resource/template/template_funcs.go` (`addCalicoFuncs`, `BGPFilterBIRDFuncs`) | Exposing `getBGPConfig` and rendering BGPFilter resources into BIRD functions. |
| BIRD export and kernel filters | `node/filesystem/etc/calico/confd/templates/bird_ipam.cfg.template` (`calico_export_to_bgp_peers`, `calico_kernel_programming`) | The filter to peers and the filter to the kernel, both driven by IP pools. |
| BIRD aggregation | `node/filesystem/etc/calico/confd/templates/bird_aggr.cfg.template` (`static_template`, `calico_aggr`) | Blackhole block routes for this node's blocks and the block aggregation export function. |

## Terms

Terms defined in the [root glossary](../GLOSSARY.md) that apply in this component:

- [Blackhole block route](../GLOSSARY.md#blackhole-block-route)
- [Cluster-route owner](../GLOSSARY.md#cluster-route-owner)
- [Elevated route](../GLOSSARY.md#elevated-route)
- [No-encap pool](../GLOSSARY.md#no-encap-pool)
- [Route priority](../GLOSSARY.md#route-priority)

### BIRD configuration

**Kernel-programming filter**:
The BIRD export filter on the kernel protocol. It decides which BGP-learned routes BIRD writes to the kernel.
Code: `node/filesystem/etc/calico/confd/templates/bird_ipam.cfg.template` (`calico_kernel_programming`).
_Avoid_: import filter (it is an export filter), kernel filter

**BGP export filter**:
The shared function every peer's export filter calls to choose what this node advertises. It also rejects routes that leave through Felix-programmed tunnel interfaces, so iBGP does not re-advertise them.
Code: `node/filesystem/etc/calico/confd/templates/bird_ipam.cfg.template` (`calico_export_to_bgp_peers`), `confd/pkg/backends/calico/bgp_processor.go` (`IBGPExportFilterForTunnelRoutes`).
_Avoid_: BGPFilter (that is the resource)

**Block aggregation**:
Exporting a confirmed block's CIDR and rejecting the more specific routes inside it, except elevated routes.
Code: `node/filesystem/etc/calico/confd/templates/bird_aggr.cfg.template` (`calico_aggr`).
_Avoid_: aggregation (on its own; LoadBalancer service aggregation is a different feature)

**krt_tunnel**:
A route attribute that exists only in Calico's fork of BIRD. It makes the kernel protocol send a route out of `tunl0`.
Code: `confd/pkg/backends/calico/bgp_processor.go` (`krt_tunnel`).

### Route priority

**Normal route priority**:
The kernel metric Felix gives ordinary workload routes, 1024 by default. BGPConfiguration and FelixConfiguration must carry the same value.
Code: `confd/pkg/backends/calico/bgp_processor.go` (`getNormalRoutePriority`), `api/pkg/apis/projectcalico/v3/bgpconfig.go` (`IPv4NormalRoutePriority`).

**Override preference**:
The BIRD `preference` of 200 given to a BGP-learned elevated route, so that it beats a local workload route for the same address.
Code: `confd/pkg/backends/calico/bgp_processor.go` (`birdOverridePreference`).

### Cluster routes and pools

**Pool encapsulation mode**:
Which encapsulation an IP pool uses, worked out from its `ipipMode` and `vxlanMode`: IPIP when `ipipMode` is Always or CrossSubnet, VXLAN when `vxlanMode` is, otherwise no-encap. "Pool encap mode" is the short form.
Code: `confd/pkg/backends/calico/bgp_processor.go` (`poolUsesIPIP`, `poolUsesVXLAN`).
_Avoid_: pool class

**Cluster-route handover**:
The window during a live `programClusterRoutes` change in which BIRD has withdrawn its cluster routes and Felix has not yet restarted to program them.
Code: `design/cluster-route-programming/DESIGN.md`.

**Leftover BIRD routes**:
Routes BIRD installed in the kernel and left in place when it exited. Felix removes the ones on the IPIP device when it owns the cluster routes for IPIP pools.
Code: `felix/routetable/ownershippol/main_route_table_policy.go` (`OwnBIRDIPIPRoutes`).
_Avoid_: orphan routes

### Peers

**Peer scope**:
Which nodes a BGP peering applies to: mesh, global, node-specific or local workload. It is a different thing from the BGPFilter `peerType`, which means eBGP or iBGP.
Code: `confd/pkg/backends/calico/bgp_processor.go` (`peerType`).
_Avoid_: peer type, peer kind

**Mesh peer**:
A peering to every other node that is not a route reflector, generated while the node-to-node mesh is on.
Code: `confd/pkg/backends/calico/bgp_processor.go` (`processMeshPeers`).
_Avoid_: full mesh peer

**Global peer**:
A BGPPeer with neither `node` nor `nodeSelector`, so it applies to every node.
Code: `confd/pkg/backends/calico/client.go` (`GlobalBGPPeerKey`).

**Node-specific peer**:
A BGPPeer applied to the nodes named by `node` or `nodeSelector`.
Code: `confd/pkg/backends/calico/client.go` (`NodeBGPPeerKey`).

**Local workload peer**:
A BGP peering to a workload on this node, chosen by a BGPPeer's `localWorkloadSelector` and found through endpoint status files.
Code: `confd/pkg/backends/calico/local_bgp_peer_watcher.go` (`LocalBGPPeerWatcher`).
_Avoid_: local peer

**Reverse peering**:
The peering confd adds on the peer node's side for symmetry, unless the BGPPeer sets `reversePeering` to Manual.
Code: `confd/pkg/backends/calico/client.go` (`updatePeersV1`).

**v1 peering**:
A peering rendered into confd's cache as a `/calico/bgp/v1/global` or `/calico/bgp/v1/host/<node>` peer key.
Code: `confd/pkg/backends/calico/client.go` (`updatePeersV1`).

### Client and templates

**Confd key space**:
The keys confd's cache holds for the templates to read: `/calico/bgp/v1/...`, `/calico/staticroutes` and `/calico/rejectcidrs`. It is not the v1 model.
Code: `confd/pkg/backends/calico/client.go` (`updateGlobalRoutes`), `libcalico-go/lib/backend/syncersv1/updateprocessors/bgpnodeprocessor.go` (`NewBGPNodeUpdateProcessor`).
_Avoid_: v1 model, etcd v1 path

**Data-source readiness**:
The per-source flag that the syncer, the route generator and the local BGP peer watcher must all set before confd renders any template.
Code: `confd/pkg/backends/calico/client.go` (`sourceReady`).
_Avoid_: in-sync (that is the syncer alone), full sync

**Advertised service route**:
A service CIDR that confd injects into the key space so BIRD advertises it.
Code: `confd/pkg/backends/calico/client.go` (`updateGlobalRoutes`).
_Avoid_: static route

**Kernel-reject CIDR**:
A service CIDR that BIRD advertises but never programs into the kernel.
Code: `confd/pkg/backends/calico/client.go` (`updateGlobalRoutes`).
_Avoid_: reject rule (that is a `*tables` rule)

**Route generator**:
The watcher of Services and EndpointSlices that advertises a per-service route from this node.
Code: `confd/pkg/backends/calico/routes.go` (`routeGenerator`).

**Template resource**:
One `conf.d` TOML entry that ties a template to its destination file and the keys it watches. It also carries the `check_cmd` and `reload_cmd`.
Code: `confd/pkg/resource/template/resource.go` (`TemplateResource`).

**Stage file**:
The temporary rendered file that BIRD checks before it replaces the destination file.
Code: `confd/pkg/resource/template/resource.go` (`TemplateResource`).
_Avoid_: candidate config

**Cache revision**:
A confd-internal counter that rises on every cache update. The template processor uses it to decide when to re-render.
Code: `confd/pkg/backends/calico/client.go` (`revisionsByPrefix`).
_Avoid_: datastore revision

**BirdBGPConfig**:
The per-IP-family structure of peers, filters, communities and pool statements that the templates render, with `BirdBGPPeer` for each peer.
Code: `confd/pkg/backends/types/bird_bgp_config.go` (`BirdBGPConfig`, `BirdBGPPeer`).

## Words that need a qualifier

| Word | Meanings in play | Say |
|---|---|---|
| peer type | a peer scope, the BGPFilter `peerType` of eBGP or iBGP | peer scope, eBGP or iBGP |
| static route | an advertised service route, a blackhole block route, a peer reachability route, a kernel-reject CIDR | name which |
| program | writing a route to the kernel, confd adding a key to its cache for advertisement | program (kernel only), advertised, reject |
| global | a global peer, the default BGPConfiguration, the `/calico/bgp/v1/global` key prefix | global peer, default BGPConfiguration |
| aggregation | block aggregation, LoadBalancer service aggregation | block aggregation, LoadBalancer service aggregation |
| priority | Felix route priority, the kernel metric, BGP local preference, BIRD preference | route priority, kernel metric, BGP local preference, BIRD preference |
