// Copyright (c) 2016-2021 Tigera, Inc. All rights reserved.

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
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/labelindex"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/serviceindex"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

var (
	gaugeNumActiveSelectors = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_active_local_selectors",
		Help: "Number of active selectors on this host.",
	})
)

func init() {
	prometheus.MustRegister(gaugeNumActiveSelectors)
}

type ipSetUpdateCallbacks interface {
	OnIPSetAdded(setID string, ipSetType proto.IPSetUpdate_IPSetType)
	OnIPSetMemberAdded(setID string, ip labelindex.IPSetMember)
	OnIPSetMemberRemoved(setID string, ip labelindex.IPSetMember)
	OnIPSetRemoved(setID string)
}

type rulesUpdateCallbacks interface {
	OnPolicyActive(model.PolicyKey, *ParsedRules)
	OnPolicyInactive(model.PolicyKey)
	OnProfileActive(model.ProfileRulesKey, *ParsedRules)
	OnProfileInactive(model.ProfileRulesKey)
}

type endpointCallbacks interface {
	OnEndpointTierUpdate(endpointKey model.Key,
		endpoint interface{},
		filteredTiers []tierInfo)
}

type configCallbacks interface {
	OnConfigUpdate(globalConfig, hostConfig map[string]string)
	OnDatastoreNotReady()
}

type passthruCallbacks interface {
	OnHostIPUpdate(hostname string, ip *net.IP)
	OnHostIPRemove(hostname string)
	OnIPPoolUpdate(model.IPPoolKey, *model.IPPool)
	OnIPPoolRemove(model.IPPoolKey)
	OnServiceAccountUpdate(*proto.ServiceAccountUpdate)
	OnServiceAccountRemove(proto.ServiceAccountID)
	OnNamespaceUpdate(*proto.NamespaceUpdate)
	OnNamespaceRemove(proto.NamespaceID)
	OnWireguardUpdate(string, *model.Wireguard)
	OnWireguardRemove(string)
	OnGlobalBGPConfigUpdate(*v3.BGPConfiguration)
}

type poolEncapCallbacks interface {
	OnIPPoolUpdate(model.IPPoolKey, *model.IPPool)
	OnIPPoolRemove(model.IPPoolKey)
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
	endpointCallbacks
	configCallbacks
	passthruCallbacks
	poolEncapCallbacks
	routeCallbacks
	vxlanCallbacks
}

type CalcGraph struct {
	// AllUpdDispatcher is the input node to the calculation graph.
	AllUpdDispatcher      *dispatcher.Dispatcher
	activeRulesCalculator *ActiveRulesCalculator
}

func NewCalculationGraph(callbacks PipelineCallbacks, conf *config.Config, encapInfo *config.EncapInfo) *CalcGraph {
	hostname := conf.FelixHostname
	log.Infof("Creating calculation graph, filtered to hostname %v", hostname)

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

	// The active rules calculator matches local endpoints against policies and profiles to figure
	// out which policies/profiles are active on this host.  Limiting to policies that apply to
	// local endpoints significantly cuts down the number of policies that Felix has to
	// render into the dataplane.
	//
	//           ...
	//        Dispatcher (all updates)
	//           /   \
	//          /     \  All Host/Workload Endpoints
	//         /       \
	//        /      Dispatcher (local updates)
	//       /            |
	//       | Policies   | Local Host/Workload Endpoints only
	//       | Profiles   |
	//       |            |
	//     Active Rules Calculator
	//              |
	//              | Locally active policies/profiles
	//             ...
	//
	activeRulesCalc := NewActiveRulesCalculator()
	activeRulesCalc.RegisterWith(localEndpointDispatcher, allUpdDispatcher)

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

	serviceIndex := serviceindex.NewServiceIndex()
	serviceIndex.RegisterWith(allUpdDispatcher)
	// Send the Service IP set member index's outputs to the dataplane.
	serviceIndex.OnMemberAdded = func(ipSetID string, member labelindex.IPSetMember) {
		if log.GetLevel() >= log.DebugLevel {
			log.WithFields(log.Fields{
				"ipSetID": ipSetID,
				"member":  member,
			}).Debug("Member added to service IP set.")
		}
		callbacks.OnIPSetMemberAdded(ipSetID, member)
	}
	serviceIndex.OnMemberRemoved = func(ipSetID string, member labelindex.IPSetMember) {
		if log.GetLevel() >= log.DebugLevel {
			log.WithFields(log.Fields{
				"ipSetID": ipSetID,
				"member":  member,
			}).Debug("Member removed from service IP set.")
		}
		callbacks.OnIPSetMemberRemoved(ipSetID, member)
	}

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
	ipsetMemberIndex := labelindex.NewSelectorAndNamedPortIndex()
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
	ipsetMemberIndex.OnMemberAdded = func(ipSetID string, member labelindex.IPSetMember) {
		if log.GetLevel() >= log.DebugLevel {
			log.WithFields(log.Fields{
				"ipSetID": ipSetID,
				"member":  member,
			}).Debug("Member added to IP set.")
		}
		callbacks.OnIPSetMemberAdded(ipSetID, member)
	}
	ipsetMemberIndex.OnMemberRemoved = func(ipSetID string, member labelindex.IPSetMember) {
		if log.GetLevel() >= log.DebugLevel {
			log.WithFields(log.Fields{
				"ipSetID": ipSetID,
				"member":  member,
			}).Debug("Member removed from IP set.")
		}
		callbacks.OnIPSetMemberRemoved(ipSetID, member)
	}

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
	activeRulesCalc.PolicyMatchListener = polResolver
	polResolver.RegisterWith(allUpdDispatcher, localEndpointDispatcher)
	// And hook its output to the callbacks.
	polResolver.Callbacks = callbacks

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
	hostIPPassthru := NewDataplanePassthru(callbacks)
	hostIPPassthru.RegisterWith(allUpdDispatcher)

	if conf.BPFEnabled || encapInfo.UseVXLANEncap || conf.WireguardEnabled {
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
	if encapInfo.UseVXLANEncap {
		vxlanResolver := NewVXLANResolver(hostname, callbacks, conf.UseNodeResourceUpdates())
		vxlanResolver.RegisterWith(allUpdDispatcher)
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

	// Register for IP Pool updates. PoolEncapManager will call ConfigChangedRestartCallback()
	// if IPIP and/or VXLAN encap use changes due to IP pool changes, so that it is
	// recalculated at Felix startup.
	//
	//        ...
	//     Dispatcher (all updates)
	//         |
	//         | IP pools
	//         |
	//       pool encap manager
	//         |
	//         |
	//         |
	//      <dataplane>
	//
	poolEncapManager := NewPoolEncapManager(callbacks, conf, encapInfo)
	poolEncapManager.RegisterWith(allUpdDispatcher)

	return &CalcGraph{
		AllUpdDispatcher:      allUpdDispatcher,
		activeRulesCalculator: activeRulesCalc,
	}
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
