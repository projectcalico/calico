// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.
//
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

package windataplane

import (
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/dataplane/windows/hns"
	"github.com/projectcalico/calico/felix/dataplane/windows/policysets"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	// cacheTimeout specifies the time after which our hns endpoint id cache
	// will be considered stale and need to be resync'd with the dataplane.
	cacheTimeout = time.Duration(10 * time.Minute)
	// suffix to use for IPv4 addresses.
	ipv4AddrSuffix = "/32"
	// envNetworkName specifies the environment variable which should be read
	// to obtain the name of the hns network for which we will be managing
	// endpoint policies.
	envNetworkName = "KUBE_NETWORK"
	// the default hns network name to use if the envNetworkName environment
	// variable does not resolve to a value
	defaultNetworkName = "(?i)calico.*"
)

var (
	ErrUnknownEndpoint = errors.New("endpoint could not be found")
	ErrUpdateFailed    = errors.New("endpoint update failed")
)

// endpointManager processes WorkloadEndpoint* updates from the datastore. Updates are
// stored and pended for processing during CompleteDeferredWork. endpointManager is also
// responsible for orchestrating a refresh of all impacted endpoints after a IPSet update.
type endpointManager struct {
	// the name of the hns network for which we will be managing endpoint policies.
	hnsNetworkRegexp *regexp.Regexp
	// the policysets dataplane to be used when looking up endpoint policies/profiles.
	policysetsDataplane policysets.PolicySetsDataplane
	// pendingWlEpUpdates stores any pending updates to be performed per endpoint.
	pendingWlEpUpdates map[types.WorkloadEndpointID]*proto.WorkloadEndpoint
	// activeWlEndpoints stores the active/current state that was applied per endpoint
	activeWlEndpoints map[types.WorkloadEndpointID]*proto.WorkloadEndpoint
	// activeWlACLPolicies stores the active/current hns policy rules that were applied per endpoint
	activeWlACLPolicies map[types.WorkloadEndpointID][]*hns.ACLPolicy
	// addressToEndpointId serves as a hns endpoint id cache. It enables us to lookup the hns
	// endpoint id for a given endpoint ip address.
	addressToEndpointId map[string]string
	// lastCacheUpdate records the last time that the addressToEndpointId map was refreshed.
	lastCacheUpdate time.Time
	hns             hnsInterface

	// pendingIPSetUpdate stores any ipset id which has been updated.
	pendingIPSetUpdate set.Set[string]

	// pendingHostAddrs is either nil if no update is pending for the host addresses, or it contains the new set of IPs.
	pendingHostAddrs []string
	// hostAddrs contains the list of IPs detected on the host.
	hostAddrs []string
}

type hnsInterface interface {
	GetHNSSupportedFeatures() hns.HNSSupportedFeatures
	HNSListEndpointRequest() ([]hns.HNSEndpoint, error)
}

func newEndpointManager(hnsInterface hnsInterface,
	policysets policysets.PolicySetsDataplane,
) *endpointManager {
	var networkName string
	if os.Getenv(envNetworkName) != "" {
		networkName = os.Getenv(envNetworkName)
		log.WithField("NetworkName", networkName).Info("Setting hns network name from environment variable")
	} else {
		networkName = defaultNetworkName
		log.WithField("NetworkName", networkName).Info("No Network Name environment variable was found, using default name")
	}
	networkNameRegexp, err := regexp.Compile(networkName)
	if err != nil {
		log.WithError(err).Panicf(
			"Supplied value (%s) for %s environment variable not a valid regular expression.",
			networkName, envNetworkName)
	}

	hostAddrs, err := net.InterfaceAddrs()
	if err != nil {
		log.WithError(err).Panic("Failed to load host interface addresses.")
	}

	hostIPv4s := extractUnicastIPv4Addrs(hostAddrs)
	sort.Strings(hostIPv4s)

	return &endpointManager{
		hns:                 hnsInterface,
		hnsNetworkRegexp:    networkNameRegexp,
		policysetsDataplane: policysets,
		addressToEndpointId: make(map[string]string),
		activeWlEndpoints:   map[types.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		activeWlACLPolicies: map[types.WorkloadEndpointID][]*hns.ACLPolicy{},
		pendingWlEpUpdates:  map[types.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		pendingIPSetUpdate:  set.New[string](),
		hostAddrs:           hostIPv4s,
	}
}

func (m *endpointManager) OnHostAddrsUpdate(hostAddrs []string) {
	m.pendingHostAddrs = hostAddrs
}

func (m *endpointManager) OnIPSetsUpdate(ipSetId string) {
	m.pendingIPSetUpdate.Add(ipSetId)
}

// OnUpdate is called by the main dataplane driver loop during the first phase. It processes
// specific types of updates from the datastore.
func (m *endpointManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	case *proto.WorkloadEndpointUpdate:
		log.WithField("workloadEndpointId", msg.Id).Info("Processing WorkloadEndpointUpdate")
		id := types.ProtoToWorkloadEndpointID(msg.GetId())
		m.pendingWlEpUpdates[id] = msg.Endpoint
	case *proto.WorkloadEndpointRemove:
		log.WithField("workloadEndpointId", msg.Id).Info("Processing WorkloadEndpointRemove")
		id := types.ProtoToWorkloadEndpointID(msg.GetId())
		m.pendingWlEpUpdates[id] = nil
	case *proto.ActivePolicyUpdate:
		if model.KindIsStaged(msg.Id.Kind) {
			log.WithField("policyID", msg.Id).Debug("Skipping ActivePolicyUpdate with staged policy")
			return
		}
		log.WithField("policyID", msg.Id).Info("Processing ActivePolicyUpdate")
		m.ProcessPolicyProfileUpdate(policysets.PolicyNamePrefix + msg.Id.Name)
	case *proto.ActiveProfileUpdate:
		log.WithField("profileId", msg.Id).Info("Processing ActiveProfileUpdate")
		m.ProcessPolicyProfileUpdate(policysets.ProfileNamePrefix + msg.Id.Name)
	}
}

// RefreshHnsEndpointCache refreshes the hns endpoint id cache if enough time has passed since the
// last refresh or if a forceRefresh is requested (may happen if the endpointManager determines that
// a required endpoint id is not present in the cache).
func (m *endpointManager) RefreshHnsEndpointCache(forceRefresh bool) error {
	if !forceRefresh && (time.Since(m.lastCacheUpdate) < cacheTimeout) {
		log.Debug("Skipping HNS endpoint cache update; cache is recent.")
		return nil
	}

	log.Info("Refreshing the endpoint cache")
	endpoints, err := m.hns.HNSListEndpointRequest()
	if err != nil {
		log.Infof("Failed to obtain HNS endpoints: %v", err)
		return err
	}

	log.Debug("Clearing the endpoint cache")
	oldCache := m.addressToEndpointId
	m.addressToEndpointId = make(map[string]string)

	debug := log.GetLevel() >= log.DebugLevel
	for _, endpoint := range endpoints {
		if endpoint.IsRemoteEndpoint {
			if debug {
				log.WithField("id", endpoint.Id).Debug("Skipping remote endpoint")
			}
			continue
		}
		if !m.hnsNetworkRegexp.MatchString(endpoint.VirtualNetworkName) {
			if debug {
				log.WithFields(log.Fields{
					"id":          endpoint.Id,
					"ourNet":      m.hnsNetworkRegexp.String(),
					"endpointNet": endpoint.VirtualNetworkName,
				}).Debug("Skipping endpoint on other HNS network")
			}
			continue
		}

		// Some CNI plugins do not clear endpoint properly when a pod has been torn down.
		// In that case, it is possible Felix sees multiple endpoints with the same IP.
		// We need to filter out inactive endpoints that do not attach to any container.
		// An endpoint is considered to be active if its state is Attached or AttachedSharing.
		// Note: Endpoint.State attribute is dependent on HNS v1 api. If hcsshim upgrades to HNS v2
		// api this will break. We then need to Reach out to Microsoft to facilate the change via HNS.
		if endpoint.State.String() != "Attached" && endpoint.State.String() != "AttachedSharing" {
			log.WithFields(log.Fields{
				"id":   endpoint.Id,
				"name": endpoint.Name,
			}).Warn("This is a stale endpoint with no container attached")
			log.WithFields(log.Fields{
				"id":               endpoint.Id,
				"name":             endpoint.Name,
				"state":            endpoint.State.String(),
				"sharedcontainers": endpoint.SharedContainers,
			}).Debug("Stale endpoint debug information")
			continue
		}
		ip := endpoint.IPAddress.String() + ipv4AddrSuffix
		logCxt := log.WithFields(log.Fields{"IPAddress": ip, "EndpointId": endpoint.Id})
		logCxt.Debug("Adding HNS Endpoint Id entry to cache")
		m.addressToEndpointId[ip] = endpoint.Id
		if _, prs := oldCache[ip]; !prs {
			logCxt.Info("Found new HNS endpoint")
		} else {
			logCxt.Debug("Endpoint already cached.")
			delete(oldCache, ip)
		}
	}

	for id := range oldCache {
		log.WithField("id", id).Info("HNS endpoint removed from cache")
	}

	log.Infof("Cache refresh is complete. %v endpoints were cached", len(m.addressToEndpointId))
	m.lastCacheUpdate = time.Now()

	return nil
}

// Refresh pendingWlEpUpdates on the event of Policy, Profile or IPSet updates.
func (m *endpointManager) refreshPendingWlEpUpdates(updatedPolicies []string) {
	if updatedPolicies == nil {
		return
	}

	log.Debugf("Checking if any active endpoint policies need to be refreshed")
	for endpointId, workload := range m.activeWlEndpoints {
		if _, present := m.pendingWlEpUpdates[endpointId]; present {
			// skip this endpoint as it is already marked as pending update
			continue
		}

		var activePolicies []string
		profilesApply := true

		if len(workload.Tiers) > 0 {
			activePolicies = append(activePolicies, policyIDsToStrings(policysets.PolicyNamePrefix, workload.Tiers[0].IngressPolicies)...)
			activePolicies = append(activePolicies, policyIDsToStrings(policysets.PolicyNamePrefix, workload.Tiers[0].EgressPolicies)...)

			if len(workload.Tiers[0].IngressPolicies) > 0 && len(workload.Tiers[0].EgressPolicies) > 0 {
				profilesApply = false
			}
		}

		if profilesApply && len(workload.ProfileIds) > 0 {
			activePolicies = append(activePolicies, profileIDsToStrings(policysets.ProfileNamePrefix, workload.ProfileIds)...)
		}

	Policies:
		for _, policyName := range activePolicies {
			for _, updatedPolicy := range updatedPolicies {
				if policyName == updatedPolicy {
					log.WithFields(log.Fields{"policyName": policyName, "endpointId": endpointId}).Info("Endpoint is being marked for policy refresh")
					m.pendingWlEpUpdates[endpointId] = workload
					break Policies
				}
			}
		}
	}
}

// ProcessIpSetUpdate is called when a IPSet has changed. The ipSetsManager will have already updated
// the IPSet itself, but the endpointManager is responsible for requesting all impacted policy sets
// to be updated and for marking all impacted endpoints as pending so that updated policies can be
// pushed to them.
func (m *endpointManager) ProcessIpSetUpdate(ipSetId string) {
	log.WithField("ipSetId", ipSetId).Debug("Requesting PolicySetsDataplane to process the IP set update")
	updatedPolicies := m.policysetsDataplane.ProcessIpSetUpdate(ipSetId)
	m.refreshPendingWlEpUpdates(updatedPolicies)
}

// ProcessPolicyProfileUpdate is called when a Policy or Profile has changed. The policySetsDataplane will have
// already updated the Policy or Profile itself, but the endpointManager is responsible for marking all
// impacted endpoints as pending so that updated policies can be pushed to them.
func (m *endpointManager) ProcessPolicyProfileUpdate(policySetId string) {
	// PolicySets updates will be done by policySetsDataplane on the update event.
	// Here we just need to refresh pendingWlEpUpdates.
	log.WithField("policySetId", policySetId).Debug("Refresh pendingWlEpUpdates")
	m.refreshPendingWlEpUpdates([]string{policySetId})
}

// CompleteDeferredWork will apply all pending updates by gathering the rules to be updated per
// endpoint and communicating them to hns. Note that CompleteDeferredWork is called during the
// second phase of the main dataplane driver loop, so all IPSet/Policy/Profile/Workload updates
// have already been processed by the various managers and we should now have a complete picture
// of the policy/rules to be applied for each pending endpoint.
func (m *endpointManager) CompleteDeferredWork() error {
	for id := range m.pendingIPSetUpdate.All() {
		m.ProcessIpSetUpdate(id)
		m.pendingIPSetUpdate.Discard(id)
	}

	if m.pendingHostAddrs != nil {
		log.WithField("update", m.pendingHostAddrs).Debug("Pending host addrs update")
		// Defensive: sort before comparison.  We do this in the poll loop too but just in case we add another source of
		// updates later.
		sort.Strings(m.pendingHostAddrs)
		sort.Strings(m.hostAddrs)
		if !reflect.DeepEqual(m.pendingHostAddrs, m.hostAddrs) {
			log.WithField("newAddresses", m.pendingHostAddrs).Info(
				"Host interface addresses changed, updating host to workload rules.")
			m.hostAddrs = m.pendingHostAddrs
			m.markAllEndpointForRefresh()
		} else {
			log.Debug("No change to host addresses")
		}
		m.pendingHostAddrs = nil
	}

	if len(m.pendingWlEpUpdates) > 0 {
		// HnsEndpointCache needs to be refreshed before endpoint manager processes any
		// WEP updates. This is because an IP address can be recycled and assigned to a
		// different endpoint since last time HnsEndpointCache been updated.
		_ = m.RefreshHnsEndpointCache(true)
	}

	// Loop through each pending update
	var missingEndpoints bool
	for id, workload := range m.pendingWlEpUpdates {
		logCxt := log.WithField("id", id)
		var endpointId string

		// A non-nil workload indicates this is a pending add or update operation
		if workload != nil {
			for _, ip := range workload.Ipv4Nets {
				var err error
				logCxt.WithField("ip", ip).Debug("Resolving workload ip to hns endpoint Id")
				endpointId, err = m.getHnsEndpointId(ip)
				if err == nil && endpointId != "" {
					// Resolution was successful
					break
				}
			}
			if endpointId == "" {
				// Failed to find the associated hns endpoint id
				logCxt.Warn("Failed to look up HNS endpoint for workload")
				missingEndpoints = true
				continue
			}

			logCxt.Info("Processing endpoint add/update")

			// Figure out which tiers apply in the ingress/egress direction.  We skip any tiers that have no policies
			// that apply to this endpoint.  At this point we're working with policy names only.
			//
			// Also note whether the default tier has policies or not. If the
			// default tier does not have policies in a direction, then a profile should be added for that direction.
			var defaultTierIngressAppliesToEP bool
			var defaultTierEgressAppliesToEP bool
			var ingressRules, egressRules [][]*hns.ACLPolicy
			for _, t := range workload.Tiers {
				log.Debugf("windows workload %v, tiers: %v", workload.Name, t.Name)
				endOfTierDrop := (t.DefaultAction != string(v3.Pass))
				if len(t.IngressPolicies) > 0 {
					if t.Name == names.DefaultTierName {
						defaultTierIngressAppliesToEP = true
					}
					policyNames := policyIDsToStrings(policysets.PolicyNamePrefix, t.IngressPolicies)
					ingressRules = append(ingressRules, m.policysetsDataplane.GetPolicySetRules(policyNames, true, endOfTierDrop))
				}
				if len(t.EgressPolicies) > 0 {
					if t.Name == names.DefaultTierName {
						defaultTierEgressAppliesToEP = true
					}
					policyNames := policyIDsToStrings(policysets.PolicyNamePrefix, t.EgressPolicies)
					egressRules = append(egressRules, m.policysetsDataplane.GetPolicySetRules(policyNames, false, endOfTierDrop))
				}
			}
			log.Debugf("default tier has ingress policies: %v, egress policies: %v", defaultTierIngressAppliesToEP, defaultTierEgressAppliesToEP)

			// If _no_ policies apply at all, then we fall through to the profiles.  Otherwise, there's no way to get
			// from policies to profiles.
			if len(ingressRules) == 0 || !defaultTierIngressAppliesToEP {
				policyNames := profileIDsToStrings(policysets.ProfileNamePrefix, workload.ProfileIds)
				ingressRules = append(ingressRules, m.policysetsDataplane.GetPolicySetRules(policyNames, true, true))
			}

			if len(egressRules) == 0 || !defaultTierEgressAppliesToEP {
				policyNames := profileIDsToStrings(policysets.ProfileNamePrefix, workload.ProfileIds)
				egressRules = append(egressRules, m.policysetsDataplane.GetPolicySetRules(policyNames, false, true))
			}

			// Flatten any tiers.
			flatIngressRules := flattenTiers(ingressRules)
			flatEgressRules := flattenTiers(egressRules)

			if log.GetLevel() >= log.DebugLevel {
				for _, rule := range flatIngressRules {
					log.WithFields(log.Fields{"rule": rule}).Debug("ingress rules after flattening")
				}
				for _, rule := range flatEgressRules {
					log.WithFields(log.Fields{"rule": rule}).Debug("egress rules after flattening")
				}
			}

			// Make sure priorities are ascending.
			rewritePriorities(flatIngressRules, policysets.PolicyRuleMaxPriority)
			rewritePriorities(flatEgressRules, policysets.PolicyRuleMaxPriority)

			// Finally, add default allow rule with a host-scope to allow traffic through
			// the host windows firewall. Required by l2bridge network.
			// We need to add host rules after priority is rewritten because the value of the priority
			// for a host rule depends on AclNoHostRulePriority feature support.
			flatIngressRules = append(flatIngressRules, m.policysetsDataplane.NewHostRule(true))
			flatEgressRules = append(flatEgressRules, m.policysetsDataplane.NewHostRule(false))

			m.activeWlEndpoints[id] = workload

			rules := m.getHnsPolicyRules(id, endpointId, flatIngressRules, flatEgressRules)
			// Check if the rules have already been applied.
			rulesApplied, ok := m.activeWlACLPolicies[id]
			if !ok || !reflect.DeepEqual(rules, rulesApplied) {
				// Apply updated rules to the endpoint.
				err := m.applyRules(id, endpointId, rules)
				if err != nil {
					// Failed to apply, this will be rescheduled and retried
					log.WithError(err).Error("Failed to apply rules update")
					return err
				}

				m.activeWlACLPolicies[id] = rules
			} else {
				logCxt := log.WithFields(log.Fields{"id": id, "endpointId": endpointId})
				logCxt.Debug("No new rules applied to the endpoint")
			}
			delete(m.pendingWlEpUpdates, id)
		} else {
			// For now, we don't need to do anything. As the endpoint is being removed, HNS will automatically
			// handle the removal of any associated policies from the dataplane for us
			logCxt.Info("Processing endpoint removal")
			delete(m.activeWlEndpoints, id)
			delete(m.activeWlACLPolicies, id)
			delete(m.pendingWlEpUpdates, id)
		}
	}

	if missingEndpoints {
		log.Warn("Failed to look up one or more HNS endpoints; will schedule a retry")
		return ErrUnknownEndpoint
	}

	return nil
}

// extractUnicastIPv4Addrs examines the raw input addresses and returns any IPv4 addresses found.
func extractUnicastIPv4Addrs(addrs []net.Addr) []string {
	var ips []string

	for _, a := range addrs {
		var ip net.IP

		switch a := a.(type) {
		case *net.IPNet:
			ip = a.IP
		case *net.IPAddr:
			ip = a.IP
		}

		if ip == nil || len(ip.To4()) == 0 {
			// Windows dataplane doesn't support IPv6 yet.
			continue
		}
		if ip.IsLoopback() {
			// Skip 127.0.0.1.
			continue
		}
		ips = append(ips, ip.String()+"/32")
	}

	return ips
}

// markAllEndpointForRefresh queues a pending update for each endpoint that doesn't already have one.
func (m *endpointManager) markAllEndpointForRefresh() {
	for k, v := range m.activeWlEndpoints {
		if _, ok := m.pendingWlEpUpdates[k]; ok {
			// Endpoint already has a pending update, make sure we don't overwrite it.
			continue
		}
		m.pendingWlEpUpdates[k] = v
	}
}

// getHnsPolicyRules gathers all of the rules for the specified policies.
func (m *endpointManager) getHnsPolicyRules(workloadId types.WorkloadEndpointID, endpointId string, inboundRules, outboundRules []*hns.ACLPolicy) []*hns.ACLPolicy {
	rules := make([]*hns.ACLPolicy, 0, len(inboundRules)+len(outboundRules)+1)

	if nodeToEp := m.nodeToEndpointRule(); nodeToEp != nil {
		log.WithField("hostAddrs", m.hostAddrs).Debug("Adding node->endpoint allow rule")
		rules = append(rules, nodeToEp)
	}
	rules = append(rules, inboundRules...)
	rules = append(rules, outboundRules...)

	return rules
}

// applyRules sends policy rules to hns as an endpoint policy update (this actually applies the rules to the dataplane).
func (m *endpointManager) applyRules(workloadId types.WorkloadEndpointID, endpointId string, rules []*hns.ACLPolicy) error {
	logCxt := log.WithFields(log.Fields{"id": workloadId, "endpointId": endpointId})
	logCxt.Info("Applying endpoint rules")

	if len(rules) > 0 {
		if log.GetLevel() >= log.DebugLevel {
			for _, rule := range rules {
				logCxt.WithField("rule", rule).Debug("Complete set of rules to be applied")
			}
		}
	} else {
		logCxt.Info("No policies/profiles were specified, all rules will be removed from this endpoint")
	}

	logCxt.Debug("Sending request to hns to apply the rules")

	endpoint := &hns.HNSEndpoint{}
	endpoint.Id = endpointId

	if err := endpoint.ApplyACLPolicy(rules...); err != nil {
		logCxt.WithError(err).Warning("Failed to apply rules. This operation will be retried.")
		return ErrUpdateFailed
	}

	return nil
}

// nodeToEndpointRule creates a HNS rule that allows traffic from the node IP to the endpoint.
func (m *endpointManager) nodeToEndpointRule() *hns.ACLPolicy {
	if len(m.hostAddrs) == 0 {
		log.Warn("Didn't detect any IPs on the host; host-to-pod traffic may be blocked.")
		return nil
	}
	aclPolicy := m.policysetsDataplane.NewRule(true, policysets.HostToEndpointRulePriority)
	aclPolicy.Action = hns.Allow
	aclPolicy.RemoteAddresses = strings.Join(m.hostAddrs, ",")
	aclPolicy.Id = "allow-host-to-endpoint"
	return aclPolicy
}

// getHnsEndpointId retrieves the hns endpoint id for the given ip address. First, a cache lookup
// is performed. If no entry is found in the cache, then we will attempt to refresh the cache. If
// the id is still not found, we fail and let the caller implement any needed retry/backoff logic.
func (m *endpointManager) getHnsEndpointId(ip string) (string, error) {
	allowRefresh := true
	for {
		// First check the endpoint cache
		id, ok := m.addressToEndpointId[ip]
		if ok {
			log.WithFields(log.Fields{"ip": ip, "id": id}).Info("Resolved hns endpoint id")
			return id, nil
		}

		if allowRefresh {
			// No cached entry was found, force refresh the cache and check again
			log.WithField("ip", ip).Debug("Cache miss, requesting a cache refresh")
			allowRefresh = false
			_ = m.RefreshHnsEndpointCache(true)
			continue
		}
		break
	}

	log.WithField("ip", ip).Info("Could not resolve hns endpoint id")
	return "", ErrUnknownEndpoint
}

// profileIDsToStrings converts a list of profile names to their string representation with prefix.
func profileIDsToStrings(prefix string, in []string) (out []string) {
	for _, s := range in {
		out = append(out, profileIDToString(prefix, s))
	}
	return
}

func profileIDToString(prefix string, name string) string {
	return fmt.Sprintf("%s%s", prefix, name)
}

// policyIDsToStrings converts a list of PolicyID to their string representation with prefix.
func policyIDsToStrings(prefix string, in []*proto.PolicyID) []string {
	var out []string
	for _, id := range in {
		out = append(out, policyIDToString(prefix, id))
	}
	return out
}

func policyIDToString(prefix string, id *proto.PolicyID) string {
	if id.Namespace != "" {
		return fmt.Sprintf("%s%s/%s/%s", prefix, id.Kind, id.Namespace, id.Name)
	}
	return fmt.Sprintf("%s%s/%s", prefix, id.Kind, id.Name)
}

// loopPollingForInterfaceAddrs periodically checks the IP addresses on the host and sends updates on the channel
// when the IPs change.
func loopPollingForInterfaceAddrs(c chan []string) {
	var lastSortedUpdate []string
	for range time.NewTicker(10 * time.Second).C {
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			log.WithError(err).Panic("Failed to get host interface addresses")
		}

		ipv4s := extractUnicastIPv4Addrs(addrs)
		sort.Strings(ipv4s)

		if reflect.DeepEqual(lastSortedUpdate, ipv4s) {
			continue
		}

		log.WithField("update", ipv4s).Debug("Interface addresses updated.")
		c <- ipv4s
	}
}
