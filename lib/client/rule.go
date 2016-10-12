// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package client

import (
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
)

// ruleActionAPIToBackend converts the rule action field value from the API
// value to the equivalent backend value.
func ruleActionAPIToBackend(action string) string {
	return action
}

// ruleActionBackendToAPI converts the rule action field value from the backend
// value to the equivalent API value.
func ruleActionBackendToAPI(action string) string {
	if action == "" {
		return "allow"
	}
	return action
}

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
		SrcNet:      ar.Source.Net,
		SrcSelector: ar.Source.Selector,
		SrcPorts:    ar.Source.Ports,
		DstTag:      ar.Destination.Tag,
		DstNet:      ar.Destination.Net,
		DstSelector: ar.Destination.Selector,
		DstPorts:    ar.Destination.Ports,

		NotSrcTag:      ar.Source.NotTag,
		NotSrcNet:      ar.Source.NotNet,
		NotSrcSelector: ar.Source.NotSelector,
		NotSrcPorts:    ar.Source.NotPorts,
		NotDstTag:      ar.Destination.NotTag,
		NotDstNet:      ar.Destination.NotNet,
		NotDstSelector: ar.Destination.NotSelector,
		NotDstPorts:    ar.Destination.NotPorts,
	}
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
	return api.Rule{
		Action:      ruleActionBackendToAPI(br.Action),
		IPVersion:   br.IPVersion,
		Protocol:    br.Protocol,
		ICMP:        icmp,
		NotProtocol: br.NotProtocol,
		NotICMP:     notICMP,
		Source: api.EntityRule{
			Tag:         br.SrcTag,
			Net:         br.SrcNet,
			Selector:    br.SrcSelector,
			Ports:       br.SrcPorts,
			NotTag:      br.NotSrcTag,
			NotNet:      br.NotSrcNet,
			NotSelector: br.NotSrcSelector,
			NotPorts:    br.NotSrcPorts,
		},

		Destination: api.EntityRule{
			Tag:         br.DstTag,
			Net:         br.DstNet,
			Selector:    br.DstSelector,
			Ports:       br.DstPorts,
			NotTag:      br.NotDstTag,
			NotNet:      br.NotDstNet,
			NotSelector: br.NotDstSelector,
			NotPorts:    br.NotDstPorts,
		},
	}
}

// rulesAPIToBackend converts an API Rule structure slice to a Backend Rule structure slice.
func rulesAPIToBackend(ars []api.Rule) []model.Rule {
	if ars == nil {
		return []model.Rule{}
	}

	brs := make([]model.Rule, len(ars))
	for idx, ar := range ars {
		brs[idx] = ruleAPIToBackend(ar)
	}
	return brs
}

// rulesBackendToAPI converts a Backend Rule structure slice to an API Rule structure slice.
func rulesBackendToAPI(brs []model.Rule) []api.Rule {
	if brs == nil {
		return nil
	}

	ars := make([]api.Rule, len(brs))
	for idx, br := range brs {
		ars[idx] = ruleBackendToAPI(br)
	}
	return ars
}
