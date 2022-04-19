// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
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
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/dataplane/windows/hcn"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	ErrUpdatesFailed = errors.New("some VXLAN route updates failed")
)

type vxlanManager struct {
	// Shim for the Windows HNS API.
	hcn hcnInterface

	// Our dependencies.
	hostname string

	// Hold pending updates.
	routesByDest map[string]*proto.RouteUpdate
	vtepsByNode  map[string]*proto.VXLANTunnelEndpointUpdate

	// VXLAN configuration.
	networkName *regexp.Regexp
	vxlanID     int
	vxlanPort   int

	// Indicates if configuration has changed since the last apply.
	dirty bool
}

type hcnInterface interface {
	ListNetworks() ([]hcn.HostComputeNetwork, error)
}

func newVXLANManager(hcn hcnInterface, hostname string, networkName *regexp.Regexp, vxlanID, port int) *vxlanManager {
	return &vxlanManager{
		hcn:          hcn,
		hostname:     hostname,
		routesByDest: map[string]*proto.RouteUpdate{},
		vtepsByNode:  map[string]*proto.VXLANTunnelEndpointUpdate{},
		networkName:  networkName,
		vxlanID:      vxlanID,
		vxlanPort:    port,
		dirty:        true,
	}
}

func (m *vxlanManager) OnUpdate(protoBufMsg interface{}) {
	switch msg := protoBufMsg.(type) {
	case *proto.RouteUpdate:
		if msg.Type == proto.RouteType_REMOTE_WORKLOAD && msg.IpPoolType == proto.IPPoolType_VXLAN {
			logrus.WithField("msg", msg).Debug("VXLAN data plane received route update")
			m.routesByDest[msg.Dst] = msg
			m.dirty = true
		} else {
			// Same processing as for RouteRemove, in case we had this destination for a
			// VXLAN route but it has now changed to non-VXLAN.
			if _, ok := m.routesByDest[msg.Dst]; ok {
				logrus.WithField("msg", msg).Debug("VXLAN data plane received non-VXLAN update for previous VXLAN route")
				m.dirty = true
			}
			delete(m.routesByDest, msg.Dst)
		}
	case *proto.RouteRemove:
		if _, ok := m.routesByDest[msg.Dst]; ok {
			logrus.WithField("msg", msg).Debug("VXLAN data plane received route remove")
			m.dirty = true
		}
		delete(m.routesByDest, msg.Dst)
	case *proto.VXLANTunnelEndpointUpdate:
		logrus.WithField("msg", msg).Debug("VXLAN data plane received VTEP update")
		if msg.Node != m.hostname { // Skip creating a route to ourselves.
			m.vtepsByNode[msg.Node] = msg
			m.dirty = true
		}
	case *proto.VXLANTunnelEndpointRemove:
		logrus.WithField("msg", msg).Debug("VXLAN data plane received VTEP remove")
		if msg.Node != m.hostname { // Can't have a route to ourselves.
			delete(m.vtepsByNode, msg.Node)
			m.dirty = true
		}
	}
}

func (m *vxlanManager) CompleteDeferredWork() error {
	if !m.dirty {
		logrus.Debug("No change since last application, nothing to do")
		return nil
	}
	// Find the right network
	networks, err := m.hcn.ListNetworks()
	if err != nil {
		logrus.WithError(err).Error("Failed to look up HNS networks.")
		return err
	}

	var network *hcn.HostComputeNetwork
	for _, n := range networks {
		if m.networkName.MatchString(n.Name) {
			network = &n
			break
		}
	}

	if network == nil {
		return fmt.Errorf("didn't find any HNS networks matching regular expression %s", m.networkName.String())
	}

	if network.Type != "Overlay" {
		if len(m.routesByDest) > 0 || len(m.vtepsByNode) > 0 {
			return fmt.Errorf("have VXLAN routes but HNS network, %s, is of wrong type: %s",
				network.Name, network.Type)
		}
	}

	// Calculate what should be there as a whole, then, below, we'll remove items that are already there from this set.
	netPolsToAdd := set.New()
	for dest, route := range m.routesByDest {
		logrus.WithFields(logrus.Fields{
			"node":  dest,
			"route": route,
		}).Debug("Currently-active route")

		vtep := m.vtepsByNode[route.DstNodeName]
		if vtep == nil {
			logrus.WithField("node", route.DstNodeName).Info("Received route without corresponding VTEP")
			continue
		}
		logrus.WithFields(logrus.Fields{"vtep": vtep, "route": route}).Debug("Found VTEP for route")

		networkPolicySettings := hcn.RemoteSubnetRoutePolicySetting{
			IsolationId:                 uint16(m.vxlanID),
			DistributedRouterMacAddress: macToWindowsFormat(vtep.Mac),
			ProviderAddress:             vtep.ParentDeviceIpv4,
			DestinationPrefix:           route.Dst,
		}

		netPolsToAdd.Add(networkPolicySettings)
	}

	// Load what's actually there.
	netPolsToRemove := set.New()
	for _, policy := range network.Policies {
		if policy.Type == hcn.RemoteSubnetRoute {
			existingPolSettings := hcn.RemoteSubnetRoutePolicySetting{}
			err = json.Unmarshal(policy.Settings, &existingPolSettings)
			if err != nil {
				logrus.Error("Failed to unmarshal existing route policy")
				return err
			}

			// Filter down to only the
			filteredPolSettings := hcn.RemoteSubnetRoutePolicySetting{
				IsolationId:                 existingPolSettings.IsolationId,
				DistributedRouterMacAddress: existingPolSettings.DistributedRouterMacAddress,
				ProviderAddress:             existingPolSettings.ProviderAddress,
				DestinationPrefix:           existingPolSettings.DestinationPrefix,
			}
			logCxt := logrus.WithField("route", existingPolSettings)
			if netPolsToAdd.Contains(filteredPolSettings) {
				logCxt.Debug("Found route that we still want")
				netPolsToAdd.Discard(filteredPolSettings)
			} else {
				logCxt.Debug("Found route that we no longer want")
				netPolsToRemove.Add(existingPolSettings)
			}
		}
	}

	wrapPolSettings := func(polSettings hcn.RemoteSubnetRoutePolicySetting) *hcn.PolicyNetworkRequest {
		polJSON, err := json.Marshal(polSettings)
		if err != nil {
			logrus.WithError(err).WithField("policy", polSettings).Error("Failed to martial HCN policy")
			return nil
		}
		pol := hcn.NetworkPolicy{
			Type:     hcn.RemoteSubnetRoute,
			Settings: polJSON,
		}
		polReq := hcn.PolicyNetworkRequest{
			Policies: []hcn.NetworkPolicy{pol},
		}
		return &polReq
	}

	// Remove routes that are no longer needed.
	netPolsToRemove.Iter(func(item interface{}) error {
		polSetting := item.(hcn.RemoteSubnetRoutePolicySetting)
		polReq := wrapPolSettings(polSetting)
		if polReq == nil {
			return nil
		}
		err = network.RemovePolicy(*polReq)
		if err != nil {
			logrus.WithError(err).WithField("request", polSetting).Error("Failed to remove unwanted VXLAN route policy")
			return nil
		}
		return set.RemoveItem
	})

	// Add new routes.
	netPolsToAdd.Iter(func(item interface{}) error {
		polReq := wrapPolSettings(item.(hcn.RemoteSubnetRoutePolicySetting))
		if polReq == nil {
			return nil
		}
		err = network.AddPolicy(*polReq)
		if err != nil {
			logrus.WithError(err).WithField("request", polReq).Error("Failed to add VXLAN route policy")
			return nil
		}
		return set.RemoveItem
	})

	// Wrap up and check for errors.
	if netPolsToAdd.Len() == 0 && netPolsToRemove.Len() == 0 {
		logrus.Info("All VXLAN route updates succeeded.")
		m.dirty = false
	} else {
		logrus.WithFields(logrus.Fields{
			"numFailedAdds":    netPolsToAdd.Len(),
			"numFailedRemoves": netPolsToRemove.Len(),
		}).Error("Not all VXLAN route updates succeeded.")
		return ErrUpdatesFailed
	}

	return nil
}

func macToWindowsFormat(linuxFormat string) string {
	windowsFormat := strings.Replace(linuxFormat, ":", "-", -1)
	return windowsFormat
}
