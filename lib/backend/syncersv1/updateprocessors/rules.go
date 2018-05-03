// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.

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

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/selector/parser"
)

func RulesAPIV2ToBackend(ars []apiv3.Rule, ns string) []model.Rule {
	if len(ars) == 0 {
		return nil
	}

	brs := make([]model.Rule, len(ars))
	for idx, ar := range ars {
		brs[idx] = RuleAPIV2ToBackend(ar, ns)
	}
	return brs
}

// entityRuleAPIV2ToBackend collects the ordered set of selectors for the EntityRule:
// (serviceAccountSelector) && (selector)
// It also returns the namespace selector to use
func entityRuleAPIV2TOBackend(er *apiv3.EntityRule, ns string) (nsSelector, selector string) {

	// Determine which namespaces are impacted by this entityRule.
	if er.NamespaceSelector != "" {
		// A namespace selector was given - the rule applies to all namespaces
		// which match this selector.
		nsSelector = parseSelectorAttachPrefix(er.NamespaceSelector, conversion.NamespaceLabelPrefix)

		// We treat "all()" as "select all namespaces". Since in the v1 data model "all()" will select
		// all endpoints, translate this to an equivalent expressions which means select any workload that
		// is in a namespace.
		nsSelector = strings.Replace(nsSelector, "all()", "has(projectcalico.org/namespace)", -1)
	} else if ns != "" {
		// No namespace selector was given and this is a namespaced network policy,
		// so the rule applies only to its own namespace.
		nsSelector = fmt.Sprintf("%s == '%s'", apiv3.LabelNamespace, ns)
	}

	var selectors []string

	// Determine which service account selector.
	if er.ServiceAccounts != nil {
		// A service account selector was given - the rule applies to all serviceaccount
		// which match this selector.
		saSelector := parseServiceAccounts(er.ServiceAccounts)
		if saSelector != "" {
			selectors = append(selectors, saSelector)
		}
	}

	if er.Selector != "" {
		selectors = append(selectors, er.Selector)
	}

	if len(selectors) > 0 {
		// If it's just one selector then just return it
		// it will be enclosed in () by the caller.
		if len(selectors) == 1 {
			selector = selectors[0]
		} else {
			// Combine the selectors together
			selector = strings.Join(selectors, ") && (")
			selector = "(" + selector + ")"
		}
	}

	return
}

// RuleAPIToBackend converts an API Rule structure to a Backend Rule structure.
func RuleAPIV2ToBackend(ar apiv3.Rule, ns string) model.Rule {
	var icmpCode, icmpType, notICMPCode, notICMPType *int
	if ar.ICMP != nil {
		icmpCode = ar.ICMP.Code
		icmpType = ar.ICMP.Type
	}

	if ar.NotICMP != nil {
		notICMPCode = ar.NotICMP.Code
		notICMPType = ar.NotICMP.Type
	}

	sourceNSSelector, sourceSelector := entityRuleAPIV2TOBackend(&ar.Source, ns)

	// We need to namespace the rule's selector when converting to a v1 object.
	// This occurs when the selector (and/or SA Selector), NotSelector, or NamespaceSelector
	// is provided and either this is a namespaced NetworkPolicy object, or a
	// NamespaceSelector was defined.
	if sourceNSSelector != "" && (sourceSelector != "" || ar.Source.NotSelector != "" || ar.Source.NamespaceSelector != "") {
		logCxt := log.WithFields(log.Fields{
			"Namespace":         ns,
			"Selector(s)":       sourceSelector,
			"NamespaceSelector": sourceNSSelector,
			"NotSelector":       ar.Source.NotSelector,
		})
		logCxt.Debug("Update source Selector to include namespace")
		if sourceSelector != "" {
			sourceSelector = fmt.Sprintf("(%s) && (%s)", sourceNSSelector, sourceSelector)
		} else {
			sourceSelector = sourceNSSelector
		}
	}

	destNSSelector, destSelector := entityRuleAPIV2TOBackend(&ar.Destination, ns)
	if destNSSelector != "" && (destSelector != "" || ar.Destination.NotSelector != "" || ar.Destination.NamespaceSelector != "") {
		logCxt := log.WithFields(log.Fields{
			"Namespace":         ns,
			"Selector(s)":       destSelector,
			"NamespaceSelector": destNSSelector,
			"NotSelector":       ar.Destination.NotSelector,
		})
		logCxt.Debug("Update Destination Selector to include namespace")
		if destSelector != "" {
			destSelector = fmt.Sprintf("(%s) && (%s)", destNSSelector, destSelector)
		} else {
			destSelector = destNSSelector
		}
	}

	var srcServiceAcctMatch, dstServiceAcctMatch apiv3.ServiceAccountMatch
	if ar.Source.ServiceAccounts != nil {
		srcServiceAcctMatch = *ar.Source.ServiceAccounts
	}
	if ar.Destination.ServiceAccounts != nil {
		dstServiceAcctMatch = *ar.Destination.ServiceAccounts
	}

	r := model.Rule{
		Action:      ruleActionAPIV2ToBackend(ar.Action),
		IPVersion:   ar.IPVersion,
		Protocol:    convertV3ProtocolToV1(ar.Protocol),
		ICMPCode:    icmpCode,
		ICMPType:    icmpType,
		NotProtocol: convertV3ProtocolToV1(ar.NotProtocol),
		NotICMPCode: notICMPCode,
		NotICMPType: notICMPType,

		SrcNets:     convertStringsToNets(ar.Source.Nets),
		SrcSelector: sourceSelector,
		SrcPorts:    ar.Source.Ports,
		DstNets:     normalizeIPNets(ar.Destination.Nets),
		DstSelector: destSelector,
		DstPorts:    ar.Destination.Ports,

		NotSrcNets:     convertStringsToNets(ar.Source.NotNets),
		NotSrcSelector: ar.Source.NotSelector,
		NotSrcPorts:    ar.Source.NotPorts,
		NotDstNets:     normalizeIPNets(ar.Destination.NotNets),
		NotDstSelector: ar.Destination.NotSelector,
		NotDstPorts:    ar.Destination.NotPorts,

		OriginalSrcSelector:          ar.Source.Selector,
		OriginalSrcNamespaceSelector: ar.Source.NamespaceSelector,
		OriginalDstSelector:          ar.Destination.Selector,
		OriginalDstNamespaceSelector: ar.Destination.NamespaceSelector,
		OriginalNotSrcSelector:       ar.Source.NotSelector,
		OriginalNotDstSelector:       ar.Destination.NotSelector,

		OriginalSrcServiceAccountNames:    srcServiceAcctMatch.Names,
		OriginalSrcServiceAccountSelector: srcServiceAcctMatch.Selector,
		OriginalDstServiceAccountNames:    dstServiceAcctMatch.Names,
		OriginalDstServiceAccountSelector: dstServiceAcctMatch.Selector,
	}
	if ar.HTTP != nil {
		r.HTTPMatch = &model.HTTPMatch{Methods: ar.HTTP.Methods, Paths: ar.HTTP.Paths}
	}
	return r
}

// parseSelectorAttachPrefix takes a v3 selector and returns the appropriate v1 representation
// by prefixing the keys with the given prefix.
// If prefix is `pcns.` then the selector changes from `k == 'v'` to `pcns.k == 'v'`.
func parseSelectorAttachPrefix(s, prefix string) string {
	parsedSelector, err := parser.Parse(s)
	if err != nil {
		log.WithError(err).Errorf("Failed to parse selector: %s (for prefix) %s", s, prefix)
		return ""
	}
	parsedSelector.AcceptVisitor(parser.PrefixVisitor{Prefix: prefix})
	updated := parsedSelector.String()
	log.WithFields(log.Fields{"original": s, "updated": updated}).Debug("Updated selector")
	return updated
}

// parseServiceAccounts takes a v3 service account match and returns the appropriate v1 representation
// by converting the list of service account names into a set of service account with
// key: "projectcalico.org/serviceaccount" in { 'sa-1', 'sa-2' } AND
// by prefixing the keys with the `pcsa.` prefix. For example, `k == 'v'` becomes `pcsa.k == 'v'`.
func parseServiceAccounts(sam *apiv3.ServiceAccountMatch) string {
	var updated string
	if sam.Selector != "" {
		updated = parseSelectorAttachPrefix(sam.Selector, conversion.ServiceAccountLabelPrefix)
	}
	if len(sam.Names) == 0 {
		return updated
	}

	// Convert the list of ServiceAccounts to selector
	names := strings.Join(sam.Names, "', '")
	selectors := fmt.Sprintf("%s in { '%s' }", apiv3.LabelServiceAccount, names)

	// Normailize it now
	parsedSelector, err := parser.Parse(selectors)
	if err != nil {
		log.WithError(err).Errorf("Failed to parse service account Names: %s", selectors)
		return ""
	}

	selectors = parsedSelector.String()

	// A list of Service account names are AND'd with the selectors.
	if updated != "" {
		selectors = fmt.Sprintf("(%s) && (%s)", updated, selectors)
	}
	log.Debugf("SA Selector is: %s", selectors)
	return selectors
}

// convertV3ProtocolToV1 converts a v1 protocol string to a v3 protocol string
func convertV3ProtocolToV1(p *numorstring.Protocol) *numorstring.Protocol {
	if p != nil && p.Type == numorstring.NumOrStringString {
		p.StrVal = strings.ToLower(p.String())
	}
	return p
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
func ruleActionAPIV2ToBackend(action apiv3.Action) string {
	if action == apiv3.Pass {
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
