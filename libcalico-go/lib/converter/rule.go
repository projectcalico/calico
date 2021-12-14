// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package converter

import (
	"sync"

	log "github.com/sirupsen/logrus"

	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

// RulesAPIToBackend converts an API Rule structure slice to a Backend Rule structure slice.
func RulesAPIToBackend(ars []api.Rule) []model.Rule {
	if ars == nil {
		return []model.Rule{}
	}

	brs := make([]model.Rule, len(ars))
	for idx, ar := range ars {
		brs[idx] = ruleAPIToBackend(ar)
	}
	return brs
}

// RulesBackendToAPI converts a Backend Rule structure slice to an API Rule structure slice.
func RulesBackendToAPI(brs []model.Rule) []api.Rule {
	if brs == nil {
		return nil
	}

	ars := make([]api.Rule, len(brs))
	for idx, br := range brs {
		ars[idx] = ruleBackendToAPI(br)
	}
	return ars
}

var logDeprecationOnce sync.Once

// ruleAPIToBackend converts an API Rule structure to a Backend Rule structure.
func ruleAPIToBackend(ar api.Rule) model.Rule {
	var icmpCode, icmpType, notICMPCode, notICMPType *int
	if ar.ICMP != nil {
		icmpCode = ar.ICMP.Code
		icmpType = ar.ICMP.Type
	}

	if ar.NotICMP != nil {
		notICMPCode = ar.NotICMP.Code
		notICMPType = ar.NotICMP.Type
	}

	if ar.Source.Net != nil || ar.Source.NotNet != nil ||
		ar.Destination.Net != nil || ar.Destination.NotNet != nil {
		logDeprecationOnce.Do(func() {
			log.Warning("The Net and NotNet fields in Source/Destination " +
				"EntityRules are deprecated.  Please use Nets or NotNets.")
		})
	}

	return model.Rule{
		Action:      ruleActionAPIToBackend(ar.Action),
		IPVersion:   ar.IPVersion,
		Protocol:    ar.Protocol,
		ICMPCode:    icmpCode,
		ICMPType:    icmpType,
		NotProtocol: ar.NotProtocol,
		NotICMPCode: notICMPCode,
		NotICMPType: notICMPType,

		SrcTag:      ar.Source.Tag,
		SrcNet:      normalizeIPNet(ar.Source.Net),
		SrcNets:     normalizeIPNets(ar.Source.Nets),
		SrcSelector: ar.Source.Selector,
		SrcPorts:    ar.Source.Ports,
		DstTag:      ar.Destination.Tag,
		DstNet:      normalizeIPNet(ar.Destination.Net),
		DstNets:     normalizeIPNets(ar.Destination.Nets),
		DstSelector: ar.Destination.Selector,
		DstPorts:    ar.Destination.Ports,

		NotSrcTag:      ar.Source.NotTag,
		NotSrcNet:      normalizeIPNet(ar.Source.NotNet),
		NotSrcNets:     normalizeIPNets(ar.Source.NotNets),
		NotSrcSelector: ar.Source.NotSelector,
		NotSrcPorts:    ar.Source.NotPorts,
		NotDstTag:      ar.Destination.NotTag,
		NotDstNet:      normalizeIPNet(ar.Destination.NotNet),
		NotDstNets:     normalizeIPNets(ar.Destination.NotNets),
		NotDstSelector: ar.Destination.NotSelector,
		NotDstPorts:    ar.Destination.NotPorts,
	}
}

// normalizeIPNet converts an IPNet to a network by ensuring the IP address is correctly masked.
func normalizeIPNet(n *net.IPNet) *net.IPNet {
	if n == nil {
		return nil
	}
	return n.Network()
}

// normalizeIPNets converts an []*IPNet to a slice of networks by ensuring the IP addresses
// are correctly masked.
func normalizeIPNets(nets []*net.IPNet) []*net.IPNet {
	if nets == nil {
		return nil
	}
	out := make([]*net.IPNet, len(nets))
	for i, n := range nets {
		out[i] = normalizeIPNet(n)
	}
	return out
}

// ruleBackendToAPI convert a Backend Rule structure to an API Rule structure.
func ruleBackendToAPI(br model.Rule) api.Rule {
	var icmp, notICMP *api.ICMPFields
	if br.ICMPCode != nil || br.ICMPType != nil {
		icmp = &api.ICMPFields{
			Code: br.ICMPCode,
			Type: br.ICMPType,
		}
	}
	if br.NotICMPCode != nil || br.NotICMPType != nil {
		notICMP = &api.ICMPFields{
			Code: br.NotICMPCode,
			Type: br.NotICMPType,
		}
	}

	// Normalize the backend source Net/Nets/NotNet/NotNets
	// This is because of a bug where we didn't normalize
	// source (Not)Net(s) while converting API to backend in v1.
	br.SrcNet = normalizeIPNet(br.SrcNet)
	br.SrcNets = normalizeIPNets(br.SrcNets)
	br.NotSrcNet = normalizeIPNet(br.NotSrcNet)
	br.NotSrcNets = normalizeIPNets(br.NotSrcNets)
	// Also normalize destination (Not)Net(s) for consistency.
	br.DstNet = normalizeIPNet(br.DstNet)
	br.DstNets = normalizeIPNets(br.DstNets)
	br.NotDstNet = normalizeIPNet(br.NotDstNet)
	br.NotDstNets = normalizeIPNets(br.NotDstNets)

	return api.Rule{
		Action:      ruleActionBackendToAPI(br.Action),
		IPVersion:   br.IPVersion,
		Protocol:    br.Protocol,
		ICMP:        icmp,
		NotProtocol: br.NotProtocol,
		NotICMP:     notICMP,
		Source: api.EntityRule{
			Tag:         br.SrcTag,
			Nets:        br.AllSrcNets(),
			Selector:    br.SrcSelector,
			Ports:       br.SrcPorts,
			NotTag:      br.NotSrcTag,
			NotNets:     br.AllNotSrcNets(),
			NotSelector: br.NotSrcSelector,
			NotPorts:    br.NotSrcPorts,
		},

		Destination: api.EntityRule{
			Tag:         br.DstTag,
			Nets:        br.AllDstNets(),
			Selector:    br.DstSelector,
			Ports:       br.DstPorts,
			NotTag:      br.NotDstTag,
			NotNets:     br.AllNotDstNets(),
			NotSelector: br.NotDstSelector,
			NotPorts:    br.NotDstPorts,
		},
	}
}

// ruleActionAPIToBackend converts the rule action field value from the API
// value to the equivalent backend value.
func ruleActionAPIToBackend(action string) string {
	if action == "Pass" {
		return "next-tier"
	}
	return action
}

// ruleActionBackendToAPI converts the rule action field value from the backend
// value to the equivalent API value.
func ruleActionBackendToAPI(action string) string {
	if action == "" {
		return "allow"
	} else if action == "next-tier" {
		return "pass"
	}
	return action
}
