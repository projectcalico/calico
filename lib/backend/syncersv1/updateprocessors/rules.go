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

package updateprocessors

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	apiv2 "github.com/projectcalico/libcalico-go/lib/apis/v2"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
)

func RulesAPIV2ToBackend(ars []apiv2.Rule, ns string) []model.Rule {
	if ars == nil {
		return []model.Rule{}
	}

	brs := make([]model.Rule, len(ars))
	for idx, ar := range ars {
		brs[idx] = RuleAPIV2ToBackend(ar, ns)
	}
	return brs
}

// RuleAPIToBackend converts an API Rule structure to a Backend Rule structure.
func RuleAPIV2ToBackend(ar apiv2.Rule, ns string) model.Rule {
	var icmpCode, icmpType, notICMPCode, notICMPType *int
	if ar.ICMP != nil {
		icmpCode = ar.ICMP.Code
		icmpType = ar.ICMP.Type
	}

	if ar.NotICMP != nil {
		notICMPCode = ar.NotICMP.Code
		notICMPType = ar.NotICMP.Type
	}

	// If we have any selector specified, then we may need to add the namespace selector.
	// We do this if this policy is namespaced AND if the Selector does not have any other
	// k8s namespace (profile label) selector in it.
	// TODO this is TEMPORARY CODE:  We currently do a simple regex to search for pcns. in the
	// selector to see if we are performing k8s namespace queries.
	nsSelector := fmt.Sprintf("%s == '%s'", apiv2.LabelNamespace, ns)
	if ns != "" && (ar.Source.Selector != "" || ar.Source.NotSelector != "") {
		logCxt := log.WithFields(log.Fields{
			"Namespace":   ns,
			"Selector":    ar.Source.Selector,
			"NotSelector": ar.Source.NotSelector,
		})
		logCxt.Debug("Maybe update source Selector to include namespace")
		if !strings.Contains(ar.Source.Selector, conversion.NamespaceLabelPrefix) {
			logCxt.Debug("Updating source selector")
			if ar.Source.Selector == "" {
				ar.Source.Selector = nsSelector
			} else {
				ar.Source.Selector = fmt.Sprintf("(%s) && %s", ar.Source.Selector, nsSelector)
			}
		}
	}
	if ns != "" && (ar.Destination.Selector != "" || ar.Destination.NotSelector != "") {
		logCxt := log.WithFields(log.Fields{
			"Namespace":   ns,
			"Selector":    ar.Destination.Selector,
			"NotSelector": ar.Destination.NotSelector,
		})
		logCxt.Debug("Maybe update Destination Selector to include namespace")
		if !strings.Contains(ar.Destination.Selector, conversion.NamespaceLabelPrefix) {
			logCxt.Debug("Updating Destination selector")
			if ar.Destination.Selector == "" {
				ar.Destination.Selector = nsSelector
			} else {
				ar.Destination.Selector = fmt.Sprintf("(%s) && %s", ar.Destination.Selector, nsSelector)
			}
		}
	}

	return model.Rule{
		Action:      ruleActionAPIV2ToBackend(ar.Action),
		IPVersion:   ar.IPVersion,
		Protocol:    ar.Protocol,
		ICMPCode:    icmpCode,
		ICMPType:    icmpType,
		NotProtocol: ar.NotProtocol,
		NotICMPCode: notICMPCode,
		NotICMPType: notICMPType,

		SrcNets:     convertStringsToNets(ar.Source.Nets),
		SrcSelector: ar.Source.Selector,
		SrcPorts:    ar.Source.Ports,
		DstNets:     normalizeIPNets(ar.Destination.Nets),
		DstSelector: ar.Destination.Selector,
		DstPorts:    ar.Destination.Ports,

		NotSrcNets:     convertStringsToNets(ar.Source.NotNets),
		NotSrcSelector: ar.Source.NotSelector,
		NotSrcPorts:    ar.Source.NotPorts,
		NotDstNets:     normalizeIPNets(ar.Destination.NotNets),
		NotDstSelector: ar.Destination.NotSelector,
		NotDstPorts:    ar.Destination.NotPorts,
	}
}

// normalizeIPNet converts an IPNet to a network by ensuring the IP address is correctly masked.
func normalizeIPNet(n string) *cnet.IPNet {
	if n == "" {
		return nil
	}
	_, ipn, err := cnet.ParseCIDROrIP(n)
	if err != nil {
		return nil
	}
	return ipn.Network()
}

// normalizeIPNets converts an []*IPNet to a slice of networks by ensuring the IP addresses
// are correctly masked.
func normalizeIPNets(nets []string) []*cnet.IPNet {
	if len(nets) == 0 {
		return nil
	}
	out := make([]*cnet.IPNet, len(nets))
	for i, n := range nets {
		out[i] = normalizeIPNet(n)
	}
	return out
}

// ruleActionAPIV2ToBackend converts the rule action field value from the API
// value to the equivalent backend value.
func ruleActionAPIV2ToBackend(action apiv2.Action) string {
	if action == apiv2.Pass {
		return "next-tier"
	}
	return strings.ToLower(string(action))
}

func convertStringsToNets(strs []string) []*cnet.IPNet {
	var nets []*cnet.IPNet
	for _, str := range strs {
		_, ipn, err := cnet.ParseCIDROrIP(str)
		if err != nil {
			continue
		}
		nets = append(nets, ipn)
	}
	return nets
}
