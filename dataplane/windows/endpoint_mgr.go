//+build windows

// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
	"os"
	"strings"
	"time"

	hns "github.com/Microsoft/hcsshim"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/dataplane/windows/policysets"
	"github.com/projectcalico/felix/proto"
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
	defaultNetworkName = "l2bridge"
)

var (
	ErrorUnknownEndpoint = errors.New("Endpoint could not be found")
	ErrorUpdateFailed    = errors.New("Endpoint update failed")
)

// endpointManager processes WorkloadEndpoint* updates from the datastore. Updates are
// stored and pended for processing during CompleteDeferredWork. endpointManager is also
// responsible for orchestrating a refresh of all impacted endpoints after a IPSet update.
type endpointManager struct {
	// the name of the hns network for which we will be managing endpoint policies.
	hnsNetworkName string
	// the policysets dataplane to be used when looking up endpoint policies/profiles.
	policysetsDataplane policysets.PolicySetsDataplane
	// pendingWlEpUpdates stores any pending updates to be performed per endpoint.
	pendingWlEpUpdates map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	// activeWlEndpoints stores the active/current state that was applied per endpoint
	activeWlEndpoints map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	// addressToEndpointId serves as a hns endpoint id cache. It enables us to lookup the hns
	// endpoint id for a given endpoint ip address.
	addressToEndpointId map[string]string
	// lastCacheUpdate records the last time that the addressToEndpointId map was refreshed.
	lastCacheUpdate time.Time
}

func newEndpointManager(policysets policysets.PolicySetsDataplane) *endpointManager {
	var networkName string
	if os.Getenv(envNetworkName) != "" {
		networkName = os.Getenv(envNetworkName)
		log.WithField("NetworkName", networkName).Info("Setting hns network name from environment variable")
	} else {
		networkName = defaultNetworkName
		log.WithField("NetworkName", networkName).Info("No Network Name environment variable was found, using default name")
	}

	return &endpointManager{
		hnsNetworkName:      networkName,
		policysetsDataplane: policysets,
		addressToEndpointId: make(map[string]string),
		activeWlEndpoints:   map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		pendingWlEpUpdates:  map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
	}
}

// OnUpdate is called by the main dataplane driver loop during the first phase. It processes
// specific types of updates from the datastore.
func (m *endpointManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	case *proto.WorkloadEndpointUpdate:
		log.WithField("workloadEndpointId", msg.Id).Info("Processing WorkloadEndpointUpdate")
		m.pendingWlEpUpdates[*msg.Id] = msg.Endpoint
	case *proto.WorkloadEndpointRemove:
		log.WithField("workloadEndpointId", msg.Id).Info("Processing WorkloadEndpointRemove")
		m.pendingWlEpUpdates[*msg.Id] = nil
	case *proto.IPSetUpdate:
		log.WithField("ipSetId", msg.Id).Info("Processing IPSetUpdate")
		m.ProcessIpSetUpdate(msg.Id)
	case *proto.IPSetDeltaUpdate:
		log.WithField("ipSetId", msg.Id).Info("Processing IPSetDeltaUpdate")
		m.ProcessIpSetUpdate(msg.Id)
	}
}

// RefreshHnsEndpointCache refreshes the hns endpoint id cache if enough time has passed since the
// last refresh or if a forceRefresh is requested (may happen if the endpointManager determines that
// a required endpoint id is not present in the cache).
func (m *endpointManager) RefreshHnsEndpointCache(forceRefresh bool) error {
	if !forceRefresh && (time.Since(m.lastCacheUpdate) < cacheTimeout) {
		return nil
	}

	log.Info("Refreshing the endpoint cache")
	endpoints, err := hns.HNSListEndpointRequest()
	if err != nil {
		log.Infof("Failed to obtain HNS endpoints: %v", err)
		return err
	}

	log.Debug("Clearing the endpoint cache")
	m.addressToEndpointId = make(map[string]string)

	for _, endpoint := range endpoints {
		if strings.ToLower(endpoint.VirtualNetworkName) == strings.ToLower(m.hnsNetworkName) {
			ip := endpoint.IPAddress.String() + ipv4AddrSuffix
			log.WithFields(log.Fields{"IPAddress": ip, "EndpointId": endpoint.Id}).Debug("Adding HNS Endpoint Id entry to cache")
			m.addressToEndpointId[ip] = endpoint.Id
		}
	}

	log.Infof("Cache refresh is complete. %v endpoints were cached", len(m.addressToEndpointId))
	m.lastCacheUpdate = time.Now()

	return nil
}

// ProcessIpSetUpdate is called when a IPSet has changed. The ipSetsManager will have already updated
// the IPSet itself, but the endpointManager is responsible for requesting all impacted policy sets
// to be updated and for marking all impacted endpoints as pending so that updated policies can be
// pushed to them.
func (m *endpointManager) ProcessIpSetUpdate(ipSetId string) {
	log.WithField("ipSetId", ipSetId).Debug("Requesting PolicySetsDataplane to process the IP set update")
	updatedPolicies := m.policysetsDataplane.ProcessIpSetUpdate(ipSetId)
	if updatedPolicies == nil {
		return
	}

	log.Debugf("Checking if any active endpoint policies need to be refreshed")
	for endpointId, workload := range m.activeWlEndpoints {
		if _, present := m.pendingWlEpUpdates[endpointId]; present {
			// skip this endpoint as it is already marked as pending update
			continue
		}

		var activePolicyNames []string
		if len(workload.Tiers) > 0 {
			activePolicyNames = append(activePolicyNames, workload.Tiers[0].IngressPolicies...)
			activePolicyNames = append(activePolicyNames, workload.Tiers[0].EgressPolicies...)
		} else {
			if len(workload.ProfileIds) > 0 {
				activePolicyNames = workload.ProfileIds
			}
		}

	Policies:
		for _, policyName := range activePolicyNames {
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

// CompleteDeferredWork will apply all pending updates by gathering the rules to be updated per
// endpoint and communicating them to hns. Note that CompleteDeferredWork is called during the
// second phase of the main dataplane driver loop, so all IPSet/Policy/Profile/Workload updates
// have already been processed by the various managers and we should now have a complete picture
// of the policy/rules to be applied for each pending endpoint.
func (m *endpointManager) CompleteDeferredWork() error {
	if len(m.pendingWlEpUpdates) > 0 {
		m.RefreshHnsEndpointCache(false)
	}

	// Loop through each pending update
	for id, workload := range m.pendingWlEpUpdates {
		logCxt := log.WithField("id", id)

		var policyNames []string
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
				return ErrorUnknownEndpoint
			}

			logCxt.Info("Processing endpoint add/update")

			if len(workload.Tiers) > 0 {
				logCxt.Debug("Workload tiers are present - Policies will be applied")
				policyNames = append(policyNames, workload.Tiers[0].IngressPolicies...)
				policyNames = append(policyNames, workload.Tiers[0].EgressPolicies...)
			} else {
				if len(workload.ProfileIds) > 0 {
					logCxt.Debug("Workload tiers are not present - Profiles will be applied")
					policyNames = workload.ProfileIds
				}
			}

			err := m.applyRules(id, endpointId, policyNames)
			if err != nil {
				// Failed to apply, this will be rescheduled and retried
				return err
			}

			m.activeWlEndpoints[id] = workload
			delete(m.pendingWlEpUpdates, id)
		} else {
			// For now, we don't need to do anything. As the endpoint is being removed, HNS will automatically
			// handle the removal of any associated policies from the dataplane for us
			logCxt.Info("Processing endpoint removal")
			delete(m.activeWlEndpoints, id)
			delete(m.pendingWlEpUpdates, id)
		}
	}

	return nil
}

// applyRules gathers all of the rules for the specified policies and sends them to hns
// as an endpoint policy update (this actually applies the rules to the dataplane).
func (m *endpointManager) applyRules(workloadId proto.WorkloadEndpointID, endpointId string, policyNames []string) error {
	logCxt := log.WithFields(log.Fields{"id": workloadId, "endpointId": endpointId})
	logCxt.WithField("policies", policyNames).Info("Applying endpoint rules")

	var rules []*hns.ACLPolicy
	if len(policyNames) > 0 {
		rules = m.policysetsDataplane.GetPolicySetRules(policyNames)
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
		return ErrorUpdateFailed
	}

	return nil
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
			m.RefreshHnsEndpointCache(true)
			continue
		}
		break
	}

	log.WithField("ip", ip).Info("Could not resolve hns endpoint id")
	return "", ErrorUnknownEndpoint
}
