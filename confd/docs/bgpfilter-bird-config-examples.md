# BGPFilter Enhancement - Rendered BIRD Config Examples

This file shows how a BGPFilter resource with all possible match criteria and
operations gets rendered into the final BIRD config file. Two examples are
provided:

- **Example A**: A filter using ALL match criteria and ALL operations
- **Example B**: A minimal filter with no PeerType (for comparison)

---

## Example A: Full-featured BGPFilter with all match/operation fields

### BGPFilter YAML

```yaml
apiVersion: projectcalico.org/v3
kind: BGPFilter
metadata:
  name: full-example
spec:
  importV4:
    # Rule 1: iBGP import — match on CIDR+prefix, community, AS path, priority,
    #         interface, peer type; then set priority + add community + prepend AS path.
    - cidr: 10.244.0.0/16
      matchOperator: In
      prefixLength:
        min: 24
        max: 28
      peerType: iBGP
      communities:
        values: ["65000:100"]
      asPathPrefix: [65000]
      priority: 512
      interface: "eth0"
      action: Accept
      operations:
        - setPriority:
            value: 256
        - addCommunity:
            value: "65000:200"
        - prependASPath:
            prefix: [65001, 65002]

    # Rule 2: eBGP import — match everything, different operations.
    - cidr: 10.244.0.0/16
      matchOperator: In
      peerType: eBGP
      communities:
        values: ["65000:100:999"]          # large community match
      asPathPrefix: [65000, 65001]         # multi-ASN prefix match
      priority: 100
      action: Accept
      operations:
        - setPriority:
            value: 1024

    # Rule 3: Unconditional reject (no PeerType, no match criteria).
    - action: Reject

  exportV4:
    # Rule 1: eBGP export — CIDR, source, interface, AS path, priority, peer type,
    #         community match; add a large community + prepend AS path.
    #         Community matching on export checks communities already attached to
    #         the route (e.g. added by a prior import filter or earlier rule).
    - cidr: 192.168.0.0/16
      matchOperator: In
      source: RemotePeers
      interface: "eth1"
      peerType: eBGP
      communities:
        values: ["65000:42"]               # match routes carrying this community
      asPathPrefix: [65000, 65001]
      priority: 100
      action: Accept
      operations:
        - addCommunity:
            value: "65000:300:400"         # large community
        - prependASPath:
            prefix: [64999]

    # Rule 2: iBGP export — simple accept for a CIDR.
    - cidr: 10.0.0.0/8
      matchOperator: Equal
      peerType: iBGP
      action: Accept
```

### Step 1: BGPFilterBIRDFuncs generates BIRD function definitions

`BGPFilterBIRDFuncs` in `template_funcs.go` generates these functions. They
appear in the "BGP Filters" section of `bird.cfg`, shared by all peers.

```bird
# v4 BGPFilter full-example
function 'bgp_full-example_importFilterV4'(bool is_same_as) {
  if (is_same_as) then { if ((net ~ [ 10.244.0.0/16{24,28} ])&&((defined(ifname))&&(ifname ~ "eth0"))&&((65000, 100) ~ bgp_community)&&(bgp_path ~ [= 65000 * =])&&(krt_metric = 512)) then { krt_metric = 256; bgp_community.add((65000, 200)); bgp_path.prepend(65002); bgp_path.prepend(65001); accept; } }
  if (!is_same_as) then { if ((net ~ 10.244.0.0/16)&&((65000, 100, 999) ~ bgp_large_community)&&(bgp_path ~ [= 65000 65001 * =])&&(krt_metric = 100)) then { krt_metric = 1024; accept; } }
  reject;
}
function 'bgp_full-example_exportFilterV4'(bool is_same_as) {
  if (!is_same_as) then { if ((net ~ 192.168.0.0/16)&&((defined(source))&&(source ~ [ RTS_BGP ]))&&((defined(ifname))&&(ifname ~ "eth1"))&&((65000, 42) ~ bgp_community)&&(bgp_path ~ [= 65000 65001 * =])&&(krt_metric = 100)) then { bgp_large_community.add((65000, 300, 400)); bgp_path.prepend(64999); accept; } }
  if (is_same_as) then { if ((net = 10.0.0.0/8)) then { accept; } }
}
```

#### How each line is built (import function)

**Rule 1** (iBGP, Accept + operations):

Match conditions (AND-ed):

| Condition | BIRD expression | Go function |
|---|---|---|
| CIDR+PrefixLength | `(net ~ [ 10.244.0.0/16{24,28} ])` | `filterMatchCIDR` + `filterMatchPrefixLength` |
| Interface | `((defined(ifname))&&(ifname ~ "eth0"))` | `filterMatchInterface` |
| Communities | `((65000, 100) ~ bgp_community)` | `filterMatchCommunity` (standard) |
| ASPathPrefix | `(bgp_path ~ [= 65000 * =])` | `filterMatchASPathPrefix` |
| Priority | `(krt_metric = 512)` | `filterMatchPriority` |

Operations (in order):

| Operation | BIRD statement |
|---|---|
| SetPriority(256) | `krt_metric = 256;` |
| AddCommunity("65000:200") | `bgp_community.add((65000, 200));` |
| PrependASPath([65001, 65002]) | `bgp_path.prepend(65002); bgp_path.prepend(65001);` |

> PrependASPath iterates in reverse so 65001 ends up first in the path.

Combined body:

```
{ krt_metric = 256; bgp_community.add((65000, 200)); bgp_path.prepend(65002); bgp_path.prepend(65001); accept; }
```

PeerType=iBGP wrapping by `emitFilterRules`:

```
if (is_same_as) then { <the entire if-then statement> }
```

**Rule 2** (eBGP, Accept + operations):

Match conditions:

| Condition | BIRD expression | Notes |
|---|---|---|
| CIDR | `(net ~ 10.244.0.0/16)` | no PrefixLength this time |
| Communities | `((65000, 100, 999) ~ bgp_large_community)` | large community |
| ASPathPrefix | `(bgp_path ~ [= 65000 65001 * =])` | multi-ASN prefix match |
| Priority | `(krt_metric = 100)` | |

Operations:

| Operation | BIRD statement |
|---|---|
| SetPriority(1024) | `krt_metric = 1024;` |

PeerType=eBGP wrapping: `if (!is_same_as) then { ... }`

**Rule 3** (no PeerType, Reject, no match criteria):

- No conditions -> bare action: `reject;`
- No PeerType -> emitted unconditionally (no `is_same_as` guard)

#### How each line is built (export function)

**Rule 1** (eBGP):

- Match conditions: CIDR + Source + Interface + Communities + ASPathPrefix + Priority
- Community match on export checks communities already attached to the route.
- PeerType=eBGP -> `if (!is_same_as) then { ... }`

**Rule 2** (iBGP):

- Match: CIDR only (Equal operator -> exact match)
- PeerType=iBGP -> `if (is_same_as) then { ... }`

### Step 2: Per-peer filter calls (bgp_processor.go)

`buildImportFilter` / `buildExportFilter` in `bgp_processor.go` generate
per-peer filter calls that invoke the shared functions above.
`filterHasPeerType()` returns true for both directions, so the bool
argument is passed.

**For an iBGP peer** (peer AS 65001, node AS 65001, sameAS=true):

```
ImportFilter =
  'bgp_full-example_importFilterV4'(true);
  accept; # Prior to introduction of BGP Filters we used "import all" ...

ExportFilter =
  'bgp_full-example_exportFilterV4'(true);
  calico_export_to_bgp_peers(true);
  reject;
```

**For an eBGP peer** (peer AS 65002, node AS 65001, sameAS=false):

```
ImportFilter =
  'bgp_full-example_importFilterV4'(false);
  accept; # Prior to introduction of BGP Filters we used "import all" ...

ExportFilter =
  'bgp_full-example_exportFilterV4'(false);
  calico_export_to_bgp_peers(false);
  reject;
```

### Step 3: Final rendered BIRD config

Relevant excerpts only -- boilerplate like router id, kernel protocol, etc. omitted.

```bird
# -------------- BGP Filters ------------------
# v4 BGPFilter full-example
function 'bgp_full-example_importFilterV4'(bool is_same_as) {
  if (is_same_as) then { if ((net ~ [ 10.244.0.0/16{24,28} ])&&((defined(ifname))&&(ifname ~ "eth0"))&&((65000, 100) ~ bgp_community)&&(bgp_path ~ [= 65000 * =])&&(krt_metric = 512)) then { krt_metric = 256; bgp_community.add((65000, 200)); bgp_path.prepend(65002); bgp_path.prepend(65001); accept; } }
  if (!is_same_as) then { if ((net ~ 10.244.0.0/16)&&((65000, 100, 999) ~ bgp_large_community)&&(bgp_path ~ [= 65000 65001 * =])&&(krt_metric = 100)) then { krt_metric = 1024; accept; } }
  reject;
}
function 'bgp_full-example_exportFilterV4'(bool is_same_as) {
  if (!is_same_as) then { if ((net ~ 192.168.0.0/16)&&((defined(source))&&(source ~ [ RTS_BGP ]))&&((defined(ifname))&&(ifname ~ "eth1"))&&((65000, 42) ~ bgp_community)&&(bgp_path ~ [= 65000 65001 * =])&&(krt_metric = 100)) then { bgp_large_community.add((65000, 300, 400)); bgp_path.prepend(64999); accept; } }
  if (is_same_as) then { if ((net = 10.0.0.0/8)) then { accept; } }
}

# -------------- iBGP Peer --------------------
protocol bgp Mesh_10_0_0_2 from bgp_template {
  ttl security off;
  multihop;
  neighbor 10.0.0.2 as 65001;
  source address 10.0.0.1;
  import filter {
    'bgp_full-example_importFilterV4'(true);
    accept; # Prior to introduction of BGP Filters we used "import all" ...
  };
  export filter {
    'bgp_full-example_exportFilterV4'(true);
    calico_export_to_bgp_peers(true);
    reject;
  };
  passive on;
}

# -------------- eBGP Peer --------------------
protocol bgp Global_172_16_0_1 from bgp_template {
  ttl security off;
  multihop;
  neighbor 172.16.0.1 as 65002;
  source address 10.0.0.1;
  import filter {
    'bgp_full-example_importFilterV4'(false);
    accept; # Prior to introduction of BGP Filters we used "import all" ...
  };
  export filter {
    'bgp_full-example_exportFilterV4'(false);
    calico_export_to_bgp_peers(false);
    reject;
  };
}
```

### What happens at runtime

**iBGP peer imports a route** `10.244.5.0/24` with community `65000:100`,
AS path `[65000 ...]`, and `krt_metric=512`:

1. `'bgp_full-example_importFilterV4'(true)` is called
2. `is_same_as=true`, so Rule 1 fires:
   - All conditions match (CIDR in range, prefix /24 within {24,28}, interface
     eth0, community present, AS path starts with 65000, krt_metric=512)
   - Operations execute:
     1. krt_metric set to 256
     2. community 65000:200 added
     3. AS path prepended with 65001, 65002
   - Route accepted with modifications
3. Rule 2 is skipped (`is_same_as=true`, but rule is guarded by `!is_same_as`)

**eBGP peer imports the same route:**

1. `'bgp_full-example_importFilterV4'(false)` is called
2. `is_same_as=false`, so Rule 1 is skipped
3. Rule 2 fires (if conditions match):
   - If route has large community `65000:100:999`, AS path starts with
     `[65000, 65001]`, and `krt_metric=100` -> krt_metric set to 1024,
     route accepted
   - Otherwise falls through to Rule 3: reject

---

## Example B: Simple BGPFilter without PeerType (backward-compatible)

### BGPFilter YAML

```yaml
apiVersion: projectcalico.org/v3
kind: BGPFilter
metadata:
  name: simple-filter
spec:
  importV4:
    - cidr: 10.0.0.0/8
      matchOperator: In
      action: Reject
  exportV4:
    - cidr: 192.168.0.0/16
      matchOperator: Equal
      action: Accept
```

### Generated BIRD functions

No parameter -- backward compatible:

```bird
# v4 BGPFilter simple-filter
function 'bgp_simple-filter_importFilterV4'() {
  if ((net ~ 10.0.0.0/8)) then { reject; }
}
function 'bgp_simple-filter_exportFilterV4'() {
  if ((net = 192.168.0.0/16)) then { accept; }
}
```

### Per-peer filter calls

No argument -- `filterHasPeerType` returns false:

```bird
import filter {
  'bgp_simple-filter_importFilterV4'();
  accept; # Prior to introduction of BGP Filters we used "import all" ...
};
export filter {
  'bgp_simple-filter_exportFilterV4'();
  calico_export_to_bgp_peers(true);
  reject;
};
```

> The function signature and call site are identical to the pre-enhancement
> behavior. Existing BGPFilter resources that don't use PeerType are completely
> unaffected.

---

## Reference: Match criteria -> BIRD syntax

| Match Field | BIRD Syntax | Notes |
|---|---|---|
| CIDR (In) | `(net ~ 10.0.0.0/8)` | |
| CIDR (Equal) | `(net = 10.0.0.0/8)` | |
| CIDR (NotIn) | `(net !~ 10.0.0.0/8)` | |
| CIDR (NotEqual) | `(net != 10.0.0.0/8)` | |
| PrefixLength | `(net ~ [ 10.0.0.0/8{16,24} ])` | |
| Source | `((defined(source))&&(source ~ [ RTS_BGP ]))` | |
| Interface | `((defined(ifname))&&(ifname ~ "eth0"))` | |
| Communities (standard) | `((65000, 100) ~ bgp_community)` | |
| Communities (large) | `((65000, 100, 200) ~ bgp_large_community)` | |
| ASPathPrefix | `(bgp_path ~ [= 65000 * =])` | single ASN |
| ASPathPrefix | `(bgp_path ~ [= 65000 65001 * =])` | multi ASN |
| Priority | `(krt_metric = 512)` | |
| PeerType=iBGP | `if (is_same_as) then { <rule> }` | function-level guard |
| PeerType=eBGP | `if (!is_same_as) then { <rule> }` | function-level guard |

## Reference: Operations -> BIRD syntax

| Operation | BIRD Syntax | Notes |
|---|---|---|
| AddCommunity (standard) | `bgp_community.add((65000, 100));` | |
| AddCommunity (large) | `bgp_large_community.add((65000, 100, 200));` | |
| PrependASPath | `bgp_path.prepend(65001);` | per ASN, reversed order |
| SetPriority | `krt_metric = 256;` | |
