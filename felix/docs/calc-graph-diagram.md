<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Felix calculation graph — node overview

Hand-maintained overview of the calc-graph nodes and how they are wired,
assembled in [`felix/calc/calc_graph.go`](../calc/calc_graph.go)
(`NewCalculationGraph`). Update it when you add or rewire a node.

For the design rationale, invariants and review criteria, see
[`felix/design/calc-graph.md`](../design/calc-graph.md). For the output
contract (the protobuf messages emitted to the dataplane) see
[`dataplane.md` → The dataplane API](../design/dataplane.md#the-dataplane-api-calc-graph--dataplane-contract).

Nodes drawn with a dashed border are created conditionally (encap mode,
BPF, Istio ambient, lookup cache, etc.). Edge labels name the resource
types or callbacks that flow along each edge; they are illustrative, not
exhaustive.

```mermaid
flowchart TB
  Syncer["Syncer<br/>(datastore watch)"]

  subgraph DS["Datastore layer — syncer goroutine"]
    Decoupler["SyncerCallbacksDecoupler<br/>decouples syncer via channel"]
  end

  subgraph VAL["Calc layer — validation goroutine"]
    Validation["ValidationFilter<br/>nils out invalid resources"]
  end

  Async["AsyncCalcGraph<br/>channel handoff into graph goroutine"]

  Syncer -->|typed KVs| Decoupler
  Decoupler -->|via channel| Validation
  Validation --> Async

  subgraph CALC["Calc layer — graph-processing goroutine"]
    Dispatcher["AllUpdDispatcher<br/>fan out all KVs by type"]
    LocalDisp["localEndpointDispatcher<br/>+ endpointHostnameFilter:<br/>local WEP/HEP only"]
    RemoteDisp["remoteEndpointDispatcher<br/>+ remoteEndpointFilter:<br/>non-local WEP/HEP"]

    LMC["LiveMigrationCalculator"]
    ARC["ActiveRulesCalculator"]
    RS["RuleScanner"]
    IPSetIdx["SelectorAndNamedPortIndex<br/>(IP set member index)"]
    SvcIdx["ServiceIndex<br/>(service-based IP sets)"]
    PolRes["PolicyResolver"]
    BGP["ActiveBGPPeerCalculator"]
    HostPass["DataplanePassthru"]
    Config["ConfigBatcher"]
    Profile["ProfileDecoder"]
    Encap["EncapsulationResolver"]
    L3["L3RouteResolver"]
    VXLAN["VXLANResolver"]
    Istio["IstioCalculator"]

    Seq["EventSequencer:&nbsp;buffer,&nbsp;coalesce,&nbsp;flush&nbsp;in&nbsp;dependency&nbsp;order"]
    Stats["StatsCollector<br/>metrics / usage reporting"]
  end

  %% dispatch fan-out
  Async --> Dispatcher
  Dispatcher ==>|WEP/HEP| LocalDisp
  Dispatcher ==>|WEP/HEP| RemoteDisp

  %% live migration
  Dispatcher -->|LiveMigration| LMC
  LocalDisp -->|local WEP| LMC
  LMC -->|WEP + LM role| ARC
  LMC -->|endpoint computed data| PolRes

  %% active rules + rule scanning
  LocalDisp -->|local WEP/HEP| ARC
  Dispatcher -->|"policies, profiles, tiers"| ARC
  ARC -->|active policies/profiles| RS
  ARC ----->|policy-endpoint matches| PolRes
  RS -->|"OnPolicy/ProfileActive/Inactive"| Seq
  RS -->|OnIPSetAdded/Removed| Seq
  RS -->|selector / named-port sets| IPSetIdx
  RS -->|service-based sets| SvcIdx

  %% IP set membership
  Dispatcher ==>|"all endpoints, netsets, profiles"| IPSetIdx
  Dispatcher ==>|"endpoint slices, services"| SvcIdx
  IPSetIdx ==>|OnIPSetMemberAdded/Removed| Seq
  SvcIdx ===>|OnIPSetMemberAdded/Removed| Seq

  %% policy resolution
  Dispatcher ==>|"all policies, tiers"| PolRes
  LocalDisp -->|local endpoints| PolRes
  LocalDisp -->|local WEP/HEP| BGP
  Dispatcher -->|"BGP config, peers"| BGP
  BGP -->|endpoint BGP peer data| PolRes

  %% passthru + resolvers
  Dispatcher -->|"host metadata, IP pools, wireguard,<br/>BGP config, services"| HostPass
  Dispatcher ==>|"host IPs, config,<br/>pools, IPAM blocks"| L3
  LocalDisp --> L3
  Dispatcher -->|"node IPs, config"| VXLAN
  Dispatcher -->|config KVs| Config
  Dispatcher -->|profiles| Profile
  Dispatcher -->|IP pools| Encap

  %% Seq inputs
  HostPass --> Seq
  L3 ==>|routes| Seq
  VXLAN ==>|"VTEPs, routes"| Seq
  Config ---->|OnConfigUpdate| Seq
  Profile --->|"service accounts, namespaces"| Seq
  Encap ---->|"OnEncapUpdate<br/>(restarts Felix if changed)"| Seq
  PolRes -->|OnEndpointTierUpdate| Seq

  %% istio (ambient mesh)
  ARC -->|computed selector match| Istio
  Istio ---> IPSetIdx
  Istio --> PolRes

  %% side consumers (not part of dataplane output)
  PolRes ---->|local endpoint tiers| Cache
  RemoteDisp -->|remote endpoints| Cache["LookupsCache<br/>ep / svc / pol / ns caches<br/>(flow-log reporting)"]
  Dispatcher -->|"endpoints, services, netsets"| Cache
  ARC -->|active policy/profile| Cache
  Dispatcher --> Stats

  %% output boundary
  Seq -->|"via channel:<br/>proto.*Update"| DPConn["DataplaneConnection<br/>marshal to protobuf"]
  DPConn -->|protobuf| DP["Dataplane driver<br/>(iptables / nftables / eBPF)"]
  classDef optional stroke-dasharray:5 4;
  classDef output fill:#e6f4ea,stroke:#137333;
  classDef entry fill:#e8f0fe,stroke:#1a73e8;
  class L3,VXLAN,Istio,Cache,Stats optional;
  class Seq,DPConn,DP output;
  class Syncer,Dispatcher entry;
```
