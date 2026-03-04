// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package calc

import (
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/labelindex"
	"github.com/projectcalico/calico/felix/labelindex/ipsetmember"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/serviceindex"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

var gaugeNumActiveSelectors = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "felix_active_local_selectors",
	Help: "Number of active selectors on this host.",
})

func init() {
	prometheus.MustRegister(gaugeNumActiveSelectors)
}

type ipSetUpdateCallbacks interface {
	OnIPSetAdded(setID string, ipSetType proto.IPSetUpdate_IPSetType)
	OnIPSetMemberAdded(setID string, ip ipsetmember.IPSetMember)
	OnIPSetMemberRemoved(setID string, ip ipsetmember.IPSetMember)
	OnIPSetRemoved(setID string)
}

type rulesUpdateCallbacks interface {
	OnPolicyActive(model.PolicyKey, *ParsedRules)
	OnPolicyInactive(model.PolicyKey)
	OnProfileActive(model.ProfileRulesKey, *ParsedRules)
	OnProfileInactive(model.ProfileRulesKey)
}

type endpointCallbacks interface {
	OnEndpointTierUpdate(endpointKey model.EndpointKey,
		endpoint model.Endpoint,
		computedData []EndpointComputedData,
		peerData *EndpointBGPPeer,
		filteredTiers []TierInfo)
}

type configCallbacks interface {
	OnConfigUpdate(globalConfig, hostConfig map[string]string)
	OnDatastoreNotReady()
}

type encapCallbacks interface {
	OnEncapUpdate(encap config.Encapsulation)
}

type passthruCallbacks interface {
	OnHostIPUpdate(hostname string, ip *net.IP)
	OnHostIPRemove(hostname string)
	OnHostIPv6Update(hostname string, ip *net.IP)
	OnHostIPv6Remove(hostname string)
	OnHostMetadataUpdate(hostname string, ip4 *net.IPNet, ip6 *net.IPNet, asnumber string, labels map[string]string)
	OnHostMetadataRemove(hostname string)
	OnIPPoolUpdate(model.IPPoolKey, *model.IPPool)
	OnIPPoolRemove(model.IPPoolKey)
	OnServiceAccountUpdate(*proto.ServiceAccountUpdate)
	OnServiceAccountRemove(types.ServiceAccountID)
	OnNamespaceUpdate(*proto.NamespaceUpdate)
	OnNamespaceRemove(types.NamespaceID)
	OnWireguardUpdate(string, *model.Wireguard)
	OnWireguardRemove(string)
	OnGlobalBGPConfigUpdate(*v3.BGPConfiguration)
	OnServiceUpdate(*proto.ServiceUpdate)
	OnServiceRemove(*proto.ServiceRemove)
}

type routeCallbacks interface {
	OnRouteUpdate(update *proto.RouteUpdate)
	OnRouteRemove(dst string)
}

type vxlanCallbacks interface {
	OnVTEPUpdate(update *proto.VXLANTunnelEndpointUpdate)
	OnVTEPRemove(node string)
}

type PipelineCallbacks interface {
	ipSetUpdateCallbacks
	rulesUpdateCallbacks
	encapCallbacks
	endpointCallbacks
	configCallbacks
	passthruCallbacks
	routeCallbacks
	vxlanCallbacks
}

type CalcGraph struct {
	// AllUpdDispatcher is the input node to the calculation graph.
	AllUpdDispatcher *dispatcher.Dispatcher

	// Pointers to the other calc graph nodes; we don't use most of
	// these (because the nodes reference each other directly) but
	// they're very useful when inspecting the state of the calc graph
	// in the debugger.

	localEndpointDispatcher *dispatcher.Dispatcher
	activeRulesCalculator   *ActiveRulesCalculator
	ruleScanner             *RuleScanner
	serviceIndex            *serviceindex.ServiceIndex
	ipsetMemberIndex        *labelindex.SelectorAndNamedPortIndex
	hostIPPassthru          *DataplanePassthru
	l3RouteResolver         *L3RouteResolver
	vxlanResolver           *VXLANResolver
	configBatcher           *ConfigBatcher
	profileDecoder          *ProfileDecoder
	encapsulationResolver   *EncapsulationResolver
	policyResolver          *PolicyResolver
}

func (g *CalcGraph) OnUpdates(updates []api.Update) {
	g.AllUpdDispatcher.OnUpdates(updates)
}

func (g *CalcGraph) OnStatusUpdated(update api.SyncStatus) {
	g.AllUpdDispatcher.OnStatusUpdated(update)
}

func (g *CalcGraph) Flush() {
	g.policyResolver.Flush()
}

func NewCalculationGraph(
	callbacks PipelineCallbacks,
	cache *LookupsCache,
	conf *config.Config,
	liveCallback func(),
) *CalcGraph {
	hostname := conf.FelixHostname
	log.Infof("Creating calculation graph, filtered to hostname %v", hostname)
	cg := &CalcGraph{}

	// The source of the processing graph, this dispatcher will be fed all the updates from the
	// datastore, fanning them out to the registered receivers.
	//
	//               Syncer
	//                 ||
	//                 || All updates
	//                 \/
	//             Dispatcher (all updates)
	//                / | \
	//               /  |  \  Updates filtered by type
	//              /   |   \
	//     receiver_1  ...  receiver_n
	//
	allUpdDispatcher := dispatcher.NewDispatcher()
	cg.AllUpdDispatcher = allUpdDispatcher

	// Some of the receivers only need to know about local endpoints. Create a second dispatcher
	// that will filter out non-local endpoints.
	//
	//          ...
	//       Dispatcher (all updates)
	//          ... \
	//               \  All Host/Workload Endpoints
	//                \
	//              Dispatcher (local updates)
	//               <filter>
	//                / | \
	//               /  |  \  Local Host/Workload Endpoints only
	//              /   |   \
	//     receiver_1  ...  receiver_n
	//
	localEndpointDispatcher := dispatcher.NewDispatcher()
	(*localEndpointDispatcherReg)(localEndpointDispatcher).RegisterWith(allUpdDispatcher)
	localEndpointFilter := &endpointHostnameFilter{hostname: hostname}
	localEndpointFilter.RegisterWith(localEndpointDispatcher)
	cg.localEndpointDispatcher = localEndpointDispatcher

	// The active rules calculator matches local endpoints against policies and profiles to figure
	// out which policies/profiles are active on this host.  Limiting to policies that apply to
	// local endpoints significantly cuts down the number of policies that Felix has to
	// render into the dataplane.
	//
	//           ...
	//           Dispatcher (all updates)
	//                /\        \
	//               /  \        \  All Host/Workload Endpoints
	//              /    \        \
	//             /      \     Dispatcher (local updates)
	//            /        \             |
	//            |         \             \  Local Host/Workload
	//            |          \             \ Endpoints only
	//           / \          \             \
	// Profiles /   \ Policies \             \
	//         /     \          \             \
	//         \      \          |             \
	//          \      \         |Tiers        |
	//           \      \        |             /
	//            \      |       |            /
	//             \     |       |           /
	//              \    |       |          /
	//              Active Rules Calculator
	//                   |
	//                   | Locally active policies/profiles
	//             ...
	//
	activeRulesCalc := NewActiveRulesCalculator()
	activeRulesCalc.RegisterWith(localEndpointDispatcher, allUpdDispatcher)
	cg.activeRulesCalculator = activeRulesCalc

	// The active rules calculator only figures out which rules are active, it doesn't extract
	// any information from the rules.  The rule scanner takes the output from the active rules
	// calculator and scans the individual rules for selectors and named ports.  It
	// generates events when a new selector/named port starts/stops being used.
	//
	//             ...
	//     Active Rules Calculator
	//              |
	//              | Locally active policies/profiles
	//              |
	//         Rule scanner
	//          |    \
	//          |     \ Locally active selectors/named ports
	//          |      \
	//          |      ...
	//          |
	//          | IP set active/inactive
	//          |
	//     <dataplane>
	//
	ruleScanner := NewRuleScanner()
	// Wire up the rule scanner's inputs.
	activeRulesCalc.RuleScanner = ruleScanner
	// Send IP set added/removed events to the dataplane.  We'll hook up the other outputs
	// below.
	ruleScanner.RulesUpdateCallbacks = callbacks
	cg.ruleScanner = ruleScanner

	serviceIndex := serviceindex.NewServiceIndex()
	serviceIndex.RegisterWith(allUpdDispatcher)
	// Send the Service IP set member index's outputs to the dataplane.
	serviceIndex.OnMemberAdded = func(ipSetID string, member ipsetmember.IPSetMember) {
		if log.GetLevel() >= log.DebugLevel {
			log.WithFields(log.Fields{
				"ipSetID": ipSetID,
				"member":  member,
			}).Debug("Member added to service IP set.")
		}
		callbacks.OnIPSetMemberAdded(ipSetID, member)
	}
	serviceIndex.OnMemberRemoved = func(ipSetID string, member ipsetmember.IPSetMember) {
		if log.GetLevel() >= log.DebugLevel {
			log.WithFields(log.Fields{
				"ipSetID": ipSetID,
				"member":  member,
			}).Debug("Member removed from service IP set.")
		}
		callbacks.OnIPSetMemberRemoved(ipSetID, member)
	}
	serviceIndex.OnAlive = liveCallback
	cg.serviceIndex = serviceIndex

	// The rule scanner only goes as far as figuring out which selectors/named ports are
	// active. Next we need to figure out which endpoints (and hence which IP addresses/ports) are
	// in each tag/selector/named port. The IP set member index calculates the set of IPs and named
	// ports that should be in each IP set.  To do that, it matches the active selectors/named
	// ports extracted by the rule scanner against all the endpoints. The service index does the same
	// for service based rules, building IP set contributions from endpoint slices.
	//
	//        ...
	//     Dispatcher (all updates)
	//      |
	//      | All endpoints
	//      |
	//      |       ...
	//      |    Rule scanner
	//      |     |       \
	//      |    ...       \ Locally active selectors/named ports
	//       \              |
	//        \_____        |
	//              \       |
	//            IP set member index / service index
	//                   |
	//                   | IP set member added/removed
	//                   |
	//               <dataplane>
	//
	ipsetMemberIndex := labelindex.NewSelectorAndNamedPortIndex(conf.NFTablesMode == "Enabled")
	ipsetMemberIndex.OnAlive = liveCallback
	// Wire up the inputs to the IP set member index.
	ipsetMemberIndex.RegisterWith(allUpdDispatcher)
	ruleScanner.OnIPSetActive = func(ipSet *IPSetData) {
		log.WithField("ipSet", ipSet).Info("IPSet now active")
		callbacks.OnIPSetAdded(ipSet.UniqueID(), ipSet.DataplaneProtocolType())
		if ipSet.Service != "" {
			serviceIndex.UpdateIPSet(ipSet.UniqueID(), ipSet.Service)
		} else {
			ipsetMemberIndex.UpdateIPSet(ipSet.UniqueID(), ipSet.Selector, ipSet.NamedPortProtocol, ipSet.NamedPort)
		}
		gaugeNumActiveSelectors.Inc()
	}
	ruleScanner.OnIPSetInactive = func(ipSet *IPSetData) {
		log.WithField("ipSet", ipSet).Info("IPSet now inactive")
		if ipSet.Service != "" {
			serviceIndex.DeleteIPSet(ipSet.UniqueID())
		} else {
			ipsetMemberIndex.DeleteIPSet(ipSet.UniqueID())
		}
		callbacks.OnIPSetRemoved(ipSet.UniqueID())
		gaugeNumActiveSelectors.Dec()
	}

	// Send the IP set member index's outputs to the dataplane.
	ipsetMemberIndex.OnMemberAdded = func(ipSetID string, member ipsetmember.IPSetMember) {
		if log.GetLevel() >= log.DebugLevel {
			log.WithFields(log.Fields{
				"ipSetID": ipSetID,
				"member":  member,
			}).Debug("Member added to IP set.")
		}
		callbacks.OnIPSetMemberAdded(ipSetID, member)
	}
	ipsetMemberIndex.OnMemberRemoved = func(ipSetID string, member ipsetmember.IPSetMember) {
		if log.GetLevel() >= log.DebugLevel {
			log.WithFields(log.Fields{
				"ipSetID": ipSetID,
				"member":  member,
			}).Debug("Member removed from IP set.")
		}
		callbacks.OnIPSetMemberRemoved(ipSetID, member)
	}
	cg.ipsetMemberIndex = ipsetMemberIndex

	// The endpoint policy resolver marries up the active policies with local endpoints and
	// calculates the complete, ordered set of policies that apply to each endpoint.
	//
	//        ...
	//     Dispatcher (all updates)
	//      |
	//      | All policies
	//      |
	//      |       ...
	//       \   Active rules calculator
	//        \       \
	//         \       \
	//          \       | Policy X matches endpoint Y
	//           \      | Policy Z matches endpoint Y
	//            \     |
	//           Policy resolver
	//                  |
	//                  | Endpoint Y has policies [Z, X] in that order
	//                  |
	//             <dataplane>
	//
	polResolver := NewPolicyResolver()
	// Hook up the inputs to the policy resolver.
	activeRulesCalc.RegisterPolicyMatchListener(polResolver)
	polResolver.RegisterWith(allUpdDispatcher, localEndpointDispatcher)
	// And hook its output to the callbacks.
	polResolver.RegisterCallback(callbacks)
	cg.policyResolver = polResolver

	// Create and hook up the active BGP peer calculator.
	activeBGPPeerCalc := NewActiveBGPPeerCalculator(hostname)
	activeBGPPeerCalc.RegisterWith(localEndpointDispatcher, allUpdDispatcher)
	activeBGPPeerCalc.OnEndpointBGPPeerDataUpdate = polResolver.OnEndpointBGPPeerDataUpdate

	// Register for host IP updates.
	//
	//        ...
	//     Dispatcher (all updates)
	//         |
	//         | host IPs
	//         |
	//       passthru
	//         |
	//         |
	//         |
	//      <dataplane>
	//
	hostIPPassthru := NewDataplanePassthru(callbacks, conf.Ipv6Support)
	hostIPPassthru.RegisterWith(allUpdDispatcher)
	cg.hostIPPassthru = hostIPPassthru

	if conf.BPFEnabled || conf.Encapsulation.VXLANEnabled || conf.Encapsulation.VXLANEnabledV6 ||
		conf.WireguardEnabled || conf.WireguardEnabledV6 || conf.ProgramClusterRoutesEnabled() {
		// Calculate simple node-ownership routes.
		//        ...
		//     Dispatcher (all updates)
		//         |
		//         | host IPs, host config, IP pools, IPAM blocks
		//         |
		//       L3 resolver
		//         |
		//         | routes
		//         |
		//      <dataplane>
		//
		l3RR := NewL3RouteResolver(hostname, callbacks, conf.UseNodeResourceUpdates(), conf.RouteSource)
		l3RR.RegisterWith(allUpdDispatcher, localEndpointDispatcher)
		l3RR.OnAlive = liveCallback
		cg.l3RouteResolver = l3RR
	}

	// Calculate VXLAN routes.
	//        ...
	//     Dispatcher (all updates)
	//         |
	//         | host IPs, host config, IP pools, IPAM blocks
	//         |
	//       vxlan resolver
	//         |
	//         | VTEPs, routes
	//         |
	//      <dataplane>
	//
	if conf.Encapsulation.VXLANEnabled || conf.Encapsulation.VXLANEnabledV6 {
		vxlanResolver := NewVXLANResolver(hostname, callbacks, conf.UseNodeResourceUpdates())
		vxlanResolver.RegisterWith(allUpdDispatcher)
		cg.vxlanResolver = vxlanResolver
	}

	// Register for config updates.
	//
	//        ...
	//     Dispatcher (all updates)
	//         |
	//         | separate config updates foo=bar, baz=biff
	//         |
	//       config batcher
	//         |
	//         | combined config {foo=bar, bax=biff}
	//         |
	//      <dataplane>
	//
	configBatcher := NewConfigBatcher(hostname, callbacks)
	configBatcher.RegisterWith(allUpdDispatcher)
	cg.configBatcher = configBatcher

	// The profile decoder identifies objects with special dataplane significance which have
	// been encoded as profiles by libcalico-go. At present this includes Kubernetes Service
	// Accounts and Kubernetes Namespaces.
	//        ...
	//     Dispatcher (all updates)
	//         |
	//         | Profiles
	//         |
	//       profile decoder
	//         |
	//         |
	//         |
	//      <dataplane>
	//
	profileDecoder := NewProfileDecoder(callbacks)
	profileDecoder.RegisterWith(allUpdDispatcher)
	cg.profileDecoder = profileDecoder

	// The remote endpoint reverse lookup receiver only need to know about non-local endpoints.
	// Create another dispatcher that will filter out non-local endpoints.
	//
	//          ...
	//       Dispatcher (all updates)
	//         / ...
	//        / All Host/Workload Endpoints
	//       /
	//   Dispatcher (remote updates)
	//     <filter>
	remoteEndpointDispatcher := dispatcher.NewDispatcher()
	(*remoteEndpointDispatcherReg)(remoteEndpointDispatcher).RegisterWith(allUpdDispatcher)
	remoteEndpointFilter := &remoteEndpointFilter{hostname: hostname}
	remoteEndpointFilter.RegisterWith(remoteEndpointDispatcher)

	if cache != nil {
		// The lookup cache, caches endpoint (and node), networksets, policy and service information.
		//        ...
		//     Dispatcher (remote updates)
		//         |
		//         | Workload and host endpoints
		//         |
		//       lookup cache
		//
		cache.epCache.RegisterWith(allUpdDispatcher, remoteEndpointDispatcher)
		cache.svcCache.RegisterWith(allUpdDispatcher)

		// The lookup cache, caches policy information for prefix lookups. Hook into the
		// ActiveRulesCalculator to receive local active policy/profile information.
		activeRulesCalc.PolicyLookupCache = cache.polCache

		// The lookup cache, also provides local endpoint lookups and corresponding tier information.
		// Hook into the PolicyResolver to receive this information.
		polResolver.RegisterCallback(cache.epCache)

		// The lookup cache also caches networkset information for flow log reporting.
		cache.nsCache.RegisterWith(allUpdDispatcher)
	} else {
		log.Debug("lookup cache is disabled")
	}

	// Register for IP Pool updates. EncapsulationResolver will send a message to the
	// dataplane so that Felix is restarted if IPIP and/or VXLAN encapsulation changes
	// due to IP pool changes, so that it is recalculated at Felix startup.
	//
	//        ...
	//     Dispatcher (all updates)
	//         |
	//         | IP pools
	//         |
	//       encapsulation resolver
	//
	encapsulationResolver := NewEncapsulationResolver(conf, callbacks)
	encapsulationResolver.RegisterWith(allUpdDispatcher)
	cg.encapsulationResolver = encapsulationResolver

	return cg
}

type localEndpointDispatcherReg dispatcher.Dispatcher

func (l *localEndpointDispatcherReg) RegisterWith(disp *dispatcher.Dispatcher) {
	led := (*dispatcher.Dispatcher)(l)
	disp.Register(model.WorkloadEndpointKey{}, led.OnUpdate)
	disp.Register(model.HostEndpointKey{}, led.OnUpdate)
	disp.RegisterStatusHandler(led.OnDatamodelStatus)
}

// endpointHostnameFilter provides an UpdateHandler that filters out endpoints
// that are not on the given host.
type endpointHostnameFilter struct {
	hostname string
}

func (f *endpointHostnameFilter) RegisterWith(localEndpointDisp *dispatcher.Dispatcher) {
	localEndpointDisp.Register(model.WorkloadEndpointKey{}, f.OnUpdate)
	localEndpointDisp.Register(model.HostEndpointKey{}, f.OnUpdate)
}

func (f *endpointHostnameFilter) OnUpdate(update api.Update) (filterOut bool) {
	switch key := update.Key.(type) {
	case model.WorkloadEndpointKey:
		if key.Hostname != f.hostname {
			filterOut = true
		}
	case model.HostEndpointKey:
		if key.Hostname != f.hostname {
			filterOut = true
		}
	}
	if !filterOut {
		// To keep log spam down, log only for local endpoints.
		if update.Value == nil {
			log.WithField("id", update.Key).Info("Local endpoint deleted")
		} else {
			log.WithField("id", update.Key).Info("Local endpoint updated")
		}
	}
	return
}

type remoteEndpointDispatcherReg dispatcher.Dispatcher

func (l *remoteEndpointDispatcherReg) RegisterWith(disp *dispatcher.Dispatcher) {
	red := (*dispatcher.Dispatcher)(l)
	disp.Register(model.WorkloadEndpointKey{}, red.OnUpdate)
	disp.Register(model.HostEndpointKey{}, red.OnUpdate)
	disp.RegisterStatusHandler(red.OnDatamodelStatus)
}

// remoteEndpointFilter provides an UpdateHandler that filters out endpoints
// that are on the given host.
type remoteEndpointFilter struct {
	hostname string
}

func (f *remoteEndpointFilter) RegisterWith(remoteEndpointDisp *dispatcher.Dispatcher) {
	remoteEndpointDisp.Register(model.WorkloadEndpointKey{}, f.OnUpdate)
	remoteEndpointDisp.Register(model.HostEndpointKey{}, f.OnUpdate)
}

func (f *remoteEndpointFilter) OnUpdate(update api.Update) (filterOut bool) {
	switch key := update.Key.(type) {
	case model.WorkloadEndpointKey:
		if key.Hostname == f.hostname {
			filterOut = true
		}
	case model.HostEndpointKey:
		if key.Hostname == f.hostname {
			filterOut = true
		}
	}
	// Do not log for remote endpoints, since there can be many and logging each
	// will impact performance.
	return
}
